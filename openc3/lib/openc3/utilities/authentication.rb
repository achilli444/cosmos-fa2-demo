# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/version'
require 'openc3/io/json_drb'
require 'openc3/utilities/logger'
require 'openc3/utilities/env_helper'
require 'faraday'
require 'uri'

module OpenC3
  # Basic exception for known errors
  class OpenC3AuthenticationError < StandardError; end
  class OpenC3AuthenticationRetryableError < OpenC3AuthenticationError; end

  # URL schemes that carry the API password / bearer token in cleartext
  CLEARTEXT_AUTH_SCHEMES = %w(http ws).freeze
  @cleartext_auth_warned = false

  # The API schema (OPENC3_API_SCHEMA, OPENC3_SCRIPT_API_SCHEMA, ...) from the
  # environment, defaulting to https so credentials are protected in transit
  # unless a deployment explicitly chooses otherwise.
  def self.api_schema(env_var = 'OPENC3_API_SCHEMA')
    schema = ENV.fetch(env_var, nil)
    return 'https' if schema.nil? or schema.empty?

    schema
  end

  # Cleartext credential transport (http / ws) is only allowed when a
  # deployment opts in: OPENC3_ALLOW_INSECURE_AUTH for a container network
  # that is trusted or encrypted elsewhere, or OPENC3_DEVEL for local development.
  def self.insecure_auth_allowed?
    return true if EnvHelper.enabled?('OPENC3_ALLOW_INSECURE_AUTH')

    devel = ENV.fetch('OPENC3_DEVEL', nil)
    return true if devel and !devel.empty?

    false
  end

  # Verify a URL that will carry a password or token uses TLS (https / wss).
  # Raises OpenC3AuthenticationError for http / ws unless the deployment opted in,
  # in which case a warning is logged once per process.
  #
  # @param url [String] The URL credentials are about to be sent to
  # @param setting [String] The environment variable that controls the URL (for the message)
  # @return [String] The url, unchanged
  def self.verify_credential_transport(url, setting: 'OPENC3_API_SCHEMA')
    scheme = begin
      URI.parse(url.to_s).scheme.to_s.downcase
    rescue URI::InvalidURIError
      ''
    end
    return url unless CLEARTEXT_AUTH_SCHEMES.include?(scheme)

    unless insecure_auth_allowed?
      raise OpenC3AuthenticationError, "Refusing to send credentials over cleartext #{scheme} to #{url}. " \
                                       "Use https/wss (#{setting}) or set OPENC3_ALLOW_INSECURE_AUTH=1 to accept cleartext credential transport."
    end
    unless @cleartext_auth_warned
      @cleartext_auth_warned = true
      Logger.warn("Sending credentials over cleartext #{scheme} to #{url} because OPENC3_ALLOW_INSECURE_AUTH or OPENC3_DEVEL is set")
    end
    url
  end

  # @private Allow specs to re-arm the once-per-process warning
  def self.reset_cleartext_auth_warning
    @cleartext_auth_warned = false
  end

  # OpenC3 COSMOS Core authentication code
  class OpenC3Authentication
    def initialize()
      password = ENV.fetch('OPENC3_API_PASSWORD', nil)
      if password.nil?
        raise OpenC3AuthenticationError, "Authentication requires environment variable OPENC3_API_PASSWORD"
      end
      @service = password == ENV['OPENC3_SERVICE_PASSWORD']
      retry_faraday_request do
        response = _make_auth_request(password)
        @token = response.body
      end
      if @token.nil? or @token.empty?
        raise OpenC3AuthenticationError, "Authentication failed. Please check the password in the environment variable OPENC3_API_PASSWORD"
      end
    end

    # Load the token from the environment
    def token(include_bearer: true)
      @token
    end

    def get_otp(scope: 'DEFAULT')
      session_token = token()
      if session_token.nil? or session_token.empty?
        raise OpenC3AuthenticationError, "Uninitialized authentication: unable to get OTP"
      end
      retry_faraday_request do
        response = _make_otp_request(scope: scope)
        return response.body
      end
    end

    def _make_auth_request(password)
      Faraday.new.post(_generate_auth_url, JSON.generate({ 'password' => password }), {'Content-Type' => 'application/json'})
    end

    def _make_otp_request(scope: 'DEFAULT')
      params = {
        'scope' => scope
      }
      headers = {
        'Authorization' => token,
      }
      Faraday.new.get(_generate_auth_url('/auth/otp'), params, headers)
    end

    def _generate_auth_url(endpoint = nil)
      schema = OpenC3.api_schema('OPENC3_API_SCHEMA')
      hostname = ENV['OPENC3_API_HOSTNAME'] || (ENV['OPENC3_DEVEL'] ? '127.0.0.1' : 'openc3-cosmos-cmd-tlm-api')
      port = ENV['OPENC3_API_PORT'] || '2901'
      port = port.to_i
      unless endpoint
        endpoint = if @service
          "auth/verify_service"
        else
          "auth/verify"
        end
      end
      return OpenC3.verify_credential_transport("#{schema}://#{hostname}:#{port}/openc3-api/#{endpoint}")
    end

    def retry_faraday_request(max_retries: 3)
      retries = 0
      begin
        yield
      rescue Faraday::ConnectionFailed, Faraday::TimeoutError => e
        retries += 1
        if retries <= max_retries
          STDOUT.puts "Authentication request failed (attempt #{retries}/3): #{e.message}. Retrying in #{retries}s..."
          sleep(retries)
          retry
        end
        raise
      end
    end
  end

  # OpenC3 enterprise Keycloak authentication code
  class OpenC3KeycloakAuthentication < OpenC3Authentication
    # {
    #     "access_token": "",
    #     "expires_in": 600,
    #     "refresh_expires_in": 1800,
    #     "refresh_token": "",
    #     "token_type": "bearer",
    #     "id_token": "",
    #     "not-before-policy": 0,
    #     "session_state": "",
    #     "scope": "openid email profile"
    # }

    REFRESH_OFFSET_SECONDS = 60

    attr_reader :refresh_token

    # @param url [String] The url of the openc3 or keycloak in the cluster
    def initialize(url)
      OpenC3.verify_credential_transport(url, setting: 'OPENC3_KEYCLOAK_URL') if url
      @url = url
      @auth_mutex = Mutex.new
      @refresh_token = nil
      @expires_at = nil
      @refresh_expires_at = nil
      @token = nil
      @log = [nil, nil]
      @http = Faraday.new
    end

    # Load the token from the environment
    def token(include_bearer: true, openid_scope: 'openid')
      @auth_mutex.synchronize do
        @log = [nil, nil]
        current_time = Time.now.to_i
        if @token.nil?
          _make_token(current_time, openid_scope: openid_scope)
        elsif @refresh_expires_at < current_time
          _make_token(current_time, openid_scope: openid_scope)
        elsif @expires_at < current_time
          _refresh_token(current_time)
        end
      end
      if include_bearer
        return "Bearer #{@token}"
      else
        return @token
      end
    end

    def get_token_from_refresh_token(refresh_token)
      current_time = Time.now.to_i
      begin
        @refresh_token = refresh_token
        _refresh_token(current_time)
        return @token
      rescue OpenC3AuthenticationError
        return nil
      end
    end

    private

    # Make the token and save token to instance
    def _make_token(current_time, openid_scope: 'openid')
      client_id = ENV['OPENC3_API_CLIENT'] || 'api'
      if ENV['OPENC3_API_USER'] and ENV['OPENC3_API_PASSWORD']
        # Username and password
        data = {
          'username' => ENV.fetch('OPENC3_API_USER', nil),
          'password' => ENV.fetch('OPENC3_API_PASSWORD', nil),
          'client_id' => client_id,
          'grant_type' => 'password',
          'scope' => openid_scope
        }
        headers = {
          'Content-Type' => 'application/x-www-form-urlencoded',
          'User-Agent' => "OpenC3KeycloakAuthorization / #{OPENC3_VERSION} (ruby/openc3/lib/utilities/authentication)",
        }
        oath = _make_request(headers, data)
        @token = oath['access_token']
        @refresh_token = oath['refresh_token']
        @expires_at = current_time + oath['expires_in'] - REFRESH_OFFSET_SECONDS
        @refresh_expires_at = current_time + oath['refresh_expires_in'] - REFRESH_OFFSET_SECONDS
      else
        # Offline Access Token
        @refresh_token ||= ENV.fetch('OPENC3_API_TOKEN', nil)
        _refresh_token(current_time)
      end
    end

    # Refresh the token and save token to instance
    def _refresh_token(current_time)
      client_id = ENV['OPENC3_API_CLIENT'] || 'api'
      data = {
        'client_id' => client_id,
        'refresh_token' => @refresh_token,
        'grant_type' => 'refresh_token'
      }
      headers = {
        'Content-Type' => 'application/x-www-form-urlencoded',
        'User-Agent' => "OpenC3KeycloakAuthorization / #{OPENC3_VERSION} (ruby/openc3/lib/utilities/authentication)",
      }
      oath = _make_request(headers, data)
      @token = oath["access_token"]
      @refresh_token = oath["refresh_token"]
      @expires_at = current_time + oath["expires_in"] - REFRESH_OFFSET_SECONDS
      @refresh_expires_at = current_time + oath["refresh_expires_in"] - REFRESH_OFFSET_SECONDS
    end

    # Make the post request to keycloak
    def _make_request(headers, data)
      realm = ENV['OPENC3_KEYCLOAK_REALM'] || 'openc3'
      uri = URI("#{@url}/realms/#{realm}/protocol/openid-connect/token")
      # Obfuscate password and refresh token in logs unless debug mode is enabled
      if JsonDRb.debug?
        log_data = data.inspect
      else
        # Create a copy of the hash with sensitive values obfuscated
        log_data = data.dup
        log_data['password'] = '***' if log_data.key?('password')
        log_data['refresh_token'] = '***' if log_data.key?('refresh_token')
        log_data = log_data.inspect
      end
      @log[0] = "request uri: #{uri} header: #{headers} body: #{log_data}"
      STDOUT.puts @log[0] if JsonDRb.debug?
      saved_verbose = $VERBOSE; $VERBOSE = nil
      begin
        resp = @http.post(uri, URI.encode_www_form(data), headers)
      ensure
        $VERBOSE = saved_verbose
      end
      @log[1] = "response status: #{resp.status} header: #{resp.headers} body: #{resp.body}"
      STDOUT.puts @log[1] if JsonDRb.debug?
      if resp.status >= 200 && resp.status <= 299
        return JSON.parse(resp.body, allow_nan: true, create_additions: true)
      elsif resp.status >= 500 && resp.status <= 599
        raise OpenC3AuthenticationRetryableError, "authentication request retryable #{@log[0]} ::: #{@log[1]}"
      else
        raise OpenC3AuthenticationError, "authentication request failed #{@log[0]} ::: #{@log[1]}"
      end
    end
  end
end

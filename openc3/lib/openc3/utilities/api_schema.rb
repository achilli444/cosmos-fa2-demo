# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

module OpenC3
  # Raised when an API client would send credentials or data over a plaintext
  # scheme without the operator having explicitly allowed it
  class OpenC3PlaintextApiError < StandardError; end

  # Single place that resolves the URL scheme used by every API client
  # (JsonDRbObject, OpenC3Authentication, WebSocketApi, plugin / package
  # helpers). The scheme defaults to https. A plaintext scheme (http / ws)
  # is only honored when OPENC3_ALLOW_PLAINTEXT_API is set, so passwords,
  # bearer tokens, plugin gems and telemetry never leave the process
  # unencrypted because a variable was left unset.
  module ApiSchema
    DEFAULT_SCHEMA = 'https'.freeze
    SECURE_SCHEMAS = %w(https wss).freeze
    ALLOW_PLAINTEXT_VAR = 'OPENC3_ALLOW_PLAINTEXT_API'.freeze
    TRUE_VALUES = %w(1 true yes on).freeze

    @warned = {}
    @warn_mutex = Mutex.new

    # @param var [String] Environment variable holding the scheme, e.g.
    #   OPENC3_API_SCHEMA or OPENC3_SCRIPT_API_SCHEMA
    # @return [String] The scheme to use in generated URLs
    # @raise [OpenC3PlaintextApiError] if the scheme is not TLS protected and
    #   OPENC3_ALLOW_PLAINTEXT_API is not set
    def self.resolve(var = 'OPENC3_API_SCHEMA')
      schema = ENV[var].to_s.strip.downcase
      schema = DEFAULT_SCHEMA if schema.empty?
      return schema if SECURE_SCHEMAS.include?(schema)

      unless plaintext_allowed?
        raise OpenC3PlaintextApiError, "#{var}=#{schema} would send credentials and data unencrypted. " \
                                       "Set #{var}=https (the default) or explicitly set #{ALLOW_PLAINTEXT_VAR}=true to accept plaintext."
      end
      warn_plaintext(var, schema)
      schema
    end

    # WebSocket variant of resolve: http -> ws, https -> wss
    def self.resolve_websocket(var = 'OPENC3_API_SCHEMA')
      schema = resolve(var)
      case schema
      when 'https' then 'wss'
      when 'http' then 'ws'
      else schema
      end
    end

    def self.plaintext_allowed?
      TRUE_VALUES.include?(ENV[ALLOW_PLAINTEXT_VAR].to_s.strip.downcase)
    end

    # Logged once per variable per process so the override is visible in
    # script and microservice output
    def self.warn_plaintext(var, schema)
      @warn_mutex.synchronize do
        return if @warned[var]

        @warned[var] = true
      end
      STDOUT.puts "WARN: #{ALLOW_PLAINTEXT_VAR} is set: #{var}=#{schema} sends credentials and data unencrypted"
    end

    # Test hook
    def self.reset_warnings
      @warn_mutex.synchronize { @warned.clear }
    end
  end
end

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

require 'openc3/utilities/open_telemetry'

class ApiController < ApplicationController
  # JSON-RPC methods whose positional params are credentials and are never logged
  SECRET_PARAM_METHODS = %w(set_offline_access).freeze
  # JSON-RPC methods taking a (name, value) pair where the value is a secret when the name is sensitive
  NAMED_VALUE_METHODS = %w(set_setting save_setting).freeze

  def ping
    render plain: 'OK'
  end

  def api
    OpenC3.in_span('jsonrpc_api') do |span|
      req = Rack::Request.new(request.env)

      if request.post?
        request_headers = Hash[*request.env.select {|k,_v| k.start_with? 'HTTP_'}.sort.flatten]
        request_data = req.body.read
        loggable_data = redact_request_data(request_data)
        span.add_attributes({ "request_data" => loggable_data }) if span and request_data.length <= 1000
        status = nil
        content_type = nil
        body = nil
        begin
          # Intentionally log to the nil scope so we don't clog the CmdTlmServer log messages
          OpenC3::Logger.info("API data: #{loggable_data}", scope: nil, user: username())
          OpenC3::Logger.debug("API headers: #{OpenC3::Logger.redact(request_headers)}", scope: nil, user: username())
          status, content_type, body = handle_post(request_data, request_headers)
        rescue OpenC3::AuthError, OpenC3::ForbiddenError => e
          id = 1
          begin
            parsed = JSON.parse(request_data, allow_nan: true)
            id = Integer(parsed['id'])
          rescue
            OpenC3::Logger.warn("Unable to extract id from JSON-RPC message")
          end
          if OpenC3::AuthError === e
            error_code = OpenC3::JsonRpcError::ErrorCode::AUTH_ERROR
            status = 401
          else
            error_code = OpenC3::JsonRpcError::ErrorCode::FORBIDDEN_ERROR
            status = 403
          end
          response = OpenC3::JsonRpcErrorResponse.new(
            OpenC3::JsonRpcError.new(error_code, e.message, e), id
          )
          content_type = "application/json-rpc"
          body = response.to_json(allow_nan: true)
        end
      else
        status       = 405
        content_type = "text/plain"
        body         = "Request not allowed"
      end

      response_headers = { 'Content-Type' => content_type }
      # Individual tools can set 'Ignore-Errors' to an error code
      # they potentially expect, e.g. '500', or '404, 500' in which case we ignore those
      # For example in CommandSender.vue:
      # obs = this.api.cmd(targetName, commandName, paramList, {
      #   'Ignore-Errors': '500',
      # })
      if request_headers.include?('HTTP_IGNORE_ERRORS')
        response_headers['Ignore-Errors'] = request_headers['HTTP_IGNORE_ERRORS']
      end
      rack_response = Rack::Response.new([body], status, response_headers)
      self.response = ActionDispatch::Response.new(*rack_response.to_a)
      self.response.close
    end
  end

  # Build the loggable form of a JSON-RPC request body. Credentials passed as
  # parameters (set_offline_access tokens, secret settings, sensitive keyword
  # params) are replaced with OpenC3::Logger::REDACTED while the method, id and
  # non-sensitive params are preserved so the log remains useful.
  #
  # @param request_data [String] - A String of the post body from the request
  # @return [String] - Redacted request body
  def redact_request_data(request_data)
    parsed = JSON.parse(request_data, allow_nan: true)
    return OpenC3::Logger.redact(request_data) unless parsed.is_a?(Hash)

    method = parsed['method'].to_s
    params = parsed['params']
    keyword_params = parsed['keyword_params']
    if SECRET_PARAM_METHODS.include?(method) or method =~ /secret|password|token|offline_access/i
      parsed['params'] = OpenC3::Logger::REDACTED if params
    elsif NAMED_VALUE_METHODS.include?(method)
      if params.is_a?(Array) and params.length > 1 and OpenC3::Logger.sensitive_key?(params[0])
        parsed['params'] = [params[0], OpenC3::Logger::REDACTED]
      end
      if keyword_params.is_a?(Hash) and OpenC3::Logger.sensitive_key?(keyword_params['name']) and keyword_params.key?('data')
        keyword_params['data'] = OpenC3::Logger::REDACTED
      end
    end
    JSON.generate(OpenC3::Logger.redact(parsed), allow_nan: true)
  rescue StandardError
    # Not valid JSON-RPC (handle_post reports the parse error), fall back to pattern based redaction
    OpenC3::Logger.redact(request_data)
  end

  # Handles an http post.
  #
  # @param request_data [String] - A String of the post body from the request
  # @param request_headers [Hash] - A Hash of the headers from the post request
  # @return [Integer, String, String] - Http response code, content type,
  #   response body.
  def handle_post(request_data, request_headers)
    response_data, error_code = OpenC3::Cts.instance.json_drb.process_request(
      request_data: request_data,
      request_headers: request_headers,
      start_time: Time.now.sys)

    # Convert json error code into html status code
    # see http://www.jsonrpc.org/historical/json-rpc-over-http.html#errors
    if error_code
      case error_code
      when OpenC3::JsonRpcError::ErrorCode::INVALID_REQUEST    then status = 400 # Bad request
      when OpenC3::JsonRpcError::ErrorCode::AUTH_ERROR         then status = 401 # Auth
      when OpenC3::JsonRpcError::ErrorCode::FORBIDDEN_ERROR    then status = 403 # Forbidden
      when OpenC3::JsonRpcError::ErrorCode::METHOD_NOT_FOUND   then status = 404 # Not found
      when OpenC3::JsonRpcError::ErrorCode::HAZARDOUS_ERROR    then status = 409 # Server conflict
      when OpenC3::JsonRpcError::ErrorCode::CRITICAL_CMD_ERROR then status = 428 # Precondition required
      else
        # Also includes the following errors:
        # OpenC3::JsonRpcError::ErrorCode::PARSE_ERROR
        # OpenC3::JsonRpcError::ErrorCode::INVALID_PARAMS
        # OpenC3::JsonRpcError::ErrorCode::INTERNAL_ERROR
        status = 500 # Internal server error
      end
      # Note we don't log an error here because it's logged in JsonDRb::process_request
    else
      status = 200 # OK
    end
    return status, "application/json-rpc", response_data
  end
end

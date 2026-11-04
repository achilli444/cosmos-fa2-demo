# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software: you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/utilities/logger'
require 'openc3/utilities/authorization'

module OpenC3
  # Single audit hook for privileged state-changing operations. Every record
  # is written at INFO level to the scope's log stream and carries the acting
  # user, the action, its target, the parameters and the outcome so the
  # operation is attributable (AU-2, AU-3, AU-12, AC-6(9)).
  module AuditLog
    AUDIT_TAG = 'AUDIT'
    MAX_PARAM_LENGTH = 200
    REDACTED = '[FILTERED]'
    # Parameter names whose values are never written to the log
    SENSITIVE_PARAMS = /passw|secret|token|_key|crypt|salt|certificate|otp|authorization/i

    # Runs the block and records the operation and its outcome. The record is
    # written whether the block succeeds or raises; exceptions are re-raised.
    #
    # @param action [String] Name of the privileged operation, e.g. 'connect_interface'
    # @param target [String, nil] Object the operation acts on (interface, queue, scope ...)
    # @param params [Object, nil] Parameters passed to the operation
    # @param scope [String] Scope whose log stream receives the record
    # @param token [String, nil] Caller token, used to resolve the user when user is nil
    # @param user [String, nil] Already resolved username
    # @return the block's result
    def audit(action, target: nil, params: nil, scope:, token: nil, user: nil)
      user ||= audit_username(token)
      result = yield
      Logger.info(AuditLog.message(action, target, params, 'success'), scope: scope, user: user)
      result
    rescue Exception => e # rubocop:disable Lint/RescueException
      Logger.info(AuditLog.message(action, target, params, "failed: #{e.class}: #{e.message}"), scope: scope, user: user)
      raise
    end

    # Resolves the acting user from a token. Core has no user identities so
    # it reports the anonymous user; Enterprise returns the real username.
    def audit_username(token)
      info = respond_to?(:user_info, true) ? user_info(token) : {}
      username = info['username'] if info.respond_to?(:[])
      username || Authorization::ANONYMOUS_USER
    rescue StandardError
      Authorization::ANONYMOUS_USER
    end

    def self.message(action, target, params, outcome)
      msg = "#{AUDIT_TAG} #{action}"
      msg << " target=#{target}" if target
      msg << " params=#{format_params(params)}" unless params.nil? || (params.respond_to?(:empty?) && params.empty?)
      msg << " outcome=#{outcome}"
      msg
    end

    # Renders parameters for the log: sensitive keys are filtered, file
    # uploads reduced to their filename and long values truncated so a
    # script body or table binary never lands in the log stream.
    def self.format_params(params)
      case params
      when Hash
        params.map do |key, value|
          value = SENSITIVE_PARAMS.match?(key.to_s) ? REDACTED : format_params(value)
          "#{key}=#{value}"
        end.join(', ').then { |s| "{#{s}}" }
      when Array
        "[#{params.map { |v| format_params(v) }.join(', ')}]"
      else
        if params.respond_to?(:original_filename)
          "<file #{params.original_filename}>"
        else
          text = params.to_s
          text.length > MAX_PARAM_LENGTH ? "#{text[0, MAX_PARAM_LENGTH]}...(#{text.length} chars)" : text
        end
      end
    end
  end
end

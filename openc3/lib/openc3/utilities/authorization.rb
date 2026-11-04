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

require 'openc3/models/auth_model'

begin
  require 'openc3-enterprise/utilities/authorization'
rescue LoadError
  # If we're not in openc3-enterprise we define our own
  module OpenC3
    class AuthError < StandardError
    end

    class ForbiddenError < StandardError
    end

    module Authorization
      ANONYMOUS_USER = "anonymous"
      SERVICE_USER = "service"

      def self.generate_otp(user)
        username = user.is_a?(Hash) ? user['username'] : user
        raise AuthError.new("Invalid OTP user") unless username.is_a?(String) and username.start_with?(ANONYMOUS_USER)
        return OpenC3::AuthModel.generate_session(otp: true)
      end

      # Identity of the caller that presented the token. Core has a single shared
      # password so there is no named operator; the best identity the authorizer
      # has is the login session (or the service account) behind the token.
      # @return [Hash] 'username' (anonymous:<session_id>, the microservice name or
      #   'service') plus 'session' for session tokens; empty Hash if no token
      def self.user_from_token(token)
        return {} if token.nil? or token.empty?

        if OpenC3::AuthModel.service_token?(token)
          username = ENV['OPENC3_MICROSERVICE_NAME']
          username = SERVICE_USER if username.nil? or username.empty?
          return { 'username' => username, 'service' => true }
        end
        session_id = OpenC3::AuthModel.session_id(token)
        return { 'username' => ANONYMOUS_USER } unless session_id

        return { 'username' => "#{ANONYMOUS_USER}:#{session_id}", 'session' => session_id }
      end

      private

      # Raises an exception if unauthorized, otherwise returns the user Hash
      # (see user_info) so callers can attribute the action. Returns nil when
      # there is no token (internal calls, e.g. a limits response sending a command).
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        raise AuthError.new("Scope is required") unless scope

        if $openc3_authorize
          raise AuthError.new("Token is required") unless token
          unless OpenC3::AuthModel.verify(token)
            raise AuthError.new("Token is invalid")
          end
        end
        return nil if token.nil?

        return user_info(token)
      end

      def user_info(token)
        Authorization.user_from_token(token)
      end
    end
  end
end

module OpenC3
  module Authorization
    # Username to record in audit logs (CmdLog, Logger user field, limits events)
    # for the value returned by authorize or user_info in either edition.
    def self.audit_username(user)
      username = user['username'] if user.is_a?(Hash)
      username = ENV['OPENC3_MICROSERVICE_NAME'] if username.nil? or username.empty?
      username = 'anonymous' if username.nil? or username.empty?
      return username
    end
  end
end

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
      # Retained for callers that compare against the legacy return value.
      # Core no longer returns this String from authorize.
      ANONYMOUS_USER = "anonymous"

      # Permissions that transmit to a target, run code or reconfigure the
      # system. These are never granted to an identity-less session.
      COMMAND_PERMISSIONS = %w[cmd cmd_raw script_run script_edit admin superadmin tlm_set system_set].freeze

      def self.generate_otp(user)
        raise AuthError.new("Invalid OTP user") unless user.is_a?(Hash) and user['username']

        return OpenC3::AuthModel.generate_session(otp: true, user: user)
      end

      private

      # Verifies the token, maps it to the operator it was issued to and checks
      # that operator's roles grant the requested permission on the target.
      # Raises AuthError (401) or ForbiddenError (403), otherwise returns the
      # user Hash ('username', 'name', 'roles', 'targets').
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        raise AuthError.new("Scope is required") unless scope

        unless $openc3_authorize
          # Internal microservices inside the trust zone (no API boundary).
          # Attribute to the microservice rather than an anonymous user.
          return OpenC3::AuthModel.service_user
        end

        raise AuthError.new("Token is required") unless token

        user = OpenC3::AuthModel.session_user(token)
        raise AuthError.new("Token is invalid") unless user
        if Array(user['roles']).empty? and (permission.nil? or COMMAND_PERMISSIONS.include?(permission.to_s))
          raise AuthError.new("Token has no operator role; please log in again")
        end

        unless OpenC3::AuthModel.permitted?(user, permission, target_name: target_name)
          resource = target_name ? " on #{target_name}" : ''
          resource += " via #{interface_name}" if interface_name
          raise ForbiddenError.new("User '#{user['username']}' does not have permission '#{permission}'#{resource}")
        end
        return user
      end

      # @return [Hash] the user the token was issued to, or {} if unknown
      def user_info(token)
        OpenC3::AuthModel.session_user(token) || {}
      end
    end
  end
end

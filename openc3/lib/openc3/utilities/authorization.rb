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
require 'openc3/utilities/security_audit'

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

      def self.generate_otp(user)
        unless user == ANONYMOUS_USER
          SecurityAudit.authorization_failure("Invalid OTP user", user: user)
          raise AuthError.new("Invalid OTP user")
        end
        return OpenC3::AuthModel.generate_session(otp: true)
      end

      private

      # Raises an exception if unauthorized, otherwise does nothing
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        unless scope
          SecurityAudit.authorization_failure("Scope is required", permission: permission, target_name: target_name, packet_name: packet_name)
          raise AuthError.new("Scope is required")
        end

        if $openc3_authorize
          unless token
            SecurityAudit.authorization_failure("Token is required", scope: scope, permission: permission, target_name: target_name, packet_name: packet_name)
            raise AuthError.new("Token is required")
          end
          unless OpenC3::AuthModel.verify(token)
            SecurityAudit.authorization_failure("Token is invalid", scope: scope, permission: permission, target_name: target_name, packet_name: packet_name)
            raise AuthError.new("Token is invalid")
          end
        end
        return ANONYMOUS_USER
      end

      def user_info(_token)
        {} # Enterprise does stuff here
      end
    end
  end
end

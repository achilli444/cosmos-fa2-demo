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

      # Mint a one-time token bound to the same identity as the caller's session
      # so the identity survives into whatever the OTP is used for.
      def self.generate_otp(user)
        username = user.is_a?(Hash) ? user['username'] : user
        raise AuthError.new("Invalid OTP user") if username.nil? or username.to_s.empty?
        return OpenC3::AuthModel.generate_session(otp: true, username: username)
      end

      private

      # Raises an exception if unauthorized, otherwise does nothing
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        raise AuthError.new("Scope is required") unless scope

        if $openc3_authorize
          raise AuthError.new("Token is required") unless token
          unless OpenC3::AuthModel.verify(token)
            raise AuthError.new("Token is invalid")
          end
        end
        # Identity recorded on the session/service token at login so commands,
        # scripts and audit logs name a person rather than 'anonymous'
        return user_info(token)
      end

      def user_info(token)
        # Enterprise reads the Keycloak JWT here. Core reads the identity the
        # session or service token was issued to (see AuthModel#identity).
        return { 'username' => ANONYMOUS_USER } if token.nil? or token.empty?
        return OpenC3::AuthModel.identity(token)
      end
    end
  end
end

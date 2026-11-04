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

require 'openssl'
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
      # Identity recorded for callers holding OPENC3_SERVICE_PASSWORD (internal
      # services such as Script Runner). Named rather than hashed so no part of
      # that secret ever reaches a log.
      SERVICE_USER = "service"

      # Accepts the user returned by authorize (a Hash in both Core and
      # Enterprise) or the bare username for older callers.
      def self.generate_otp(user)
        username = Hash === user ? user['username'] : user
        raise AuthError.new("Invalid OTP user") unless Authorization.anonymous_username?(username)

        return OpenC3::AuthModel.generate_session(otp: true)
      end

      # Whether a username came from Core's shared password login, i.e. it is
      # ANONYMOUS_USER itself or ANONYMOUS_USER tagged with a session id.
      def self.anonymous_username?(username)
        return false unless String === username

        username == ANONYMOUS_USER or username.start_with?("#{ANONYMOUS_USER}@")
      end

      # Builds the identity recorded in audit logs for a Core caller. Core has a
      # single shared password, so there is no individual username to return;
      # instead the identity is tagged with a stable, non-reversible id derived
      # from the caller's session token (see AuthModel.session_id). Every record
      # written during one login therefore carries the same tag and can be tied
      # back to that login, without the bearer token itself appearing anywhere.
      # With no token (authorization disabled or an internal caller) the identity
      # is explicitly the untagged ANONYMOUS_USER.
      # @param token [String, nil] the session token or service password
      # @return [Hash] 'username' and 'session' (nil when no session exists)
      def self.core_user_info(token)
        return { 'username' => SERVICE_USER, 'session' => nil } if service_token?(token)

        session = OpenC3::AuthModel.session_id(token)
        return { 'username' => ANONYMOUS_USER, 'session' => nil } unless session

        { 'username' => "#{ANONYMOUS_USER}@#{session}", 'session' => session }
      end

      def self.service_token?(token)
        service_password = ENV.fetch('OPENC3_SERVICE_PASSWORD', nil)
        return false if token.nil? or service_password.nil? or service_password.empty?
        return false unless token.bytesize == service_password.bytesize

        OpenSSL.fixed_length_secure_compare(token, service_password)
      end

      private

      # Raises an exception if unauthorized, otherwise returns the caller's identity
      # (see user_info) so callers can record who performed the action.
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        raise AuthError.new("Scope is required") unless scope

        if $openc3_authorize
          raise AuthError.new("Token is required") unless token
          unless OpenC3::AuthModel.verify(token)
            raise AuthError.new("Token is invalid")
          end
        end
        return user_info(token)
      end

      # Core identity for the token. Enterprise returns the Keycloak principal
      # (username, name, roles) instead.
      def user_info(token)
        Authorization.core_user_info(token)
      end
    end
  end
end

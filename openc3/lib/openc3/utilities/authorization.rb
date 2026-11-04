# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
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
# GNU Affero General Public License for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2022, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/models/auth_model'

begin
  require 'openc3-enterprise/utilities/authorization'
rescue LoadError
  module OpenC3
    class AuthError < StandardError
    end

    class ForbiddenError < StandardError
    end

    # Core role based authorization. Every API caller (cmd-tlm-api,
    # script-runner-api, microservices, running scripts) funnels through
    # authorize so permission checks and the bound user identity live here
    # rather than in each caller. Enterprise replaces this module with the
    # Keycloak backed implementation.
    module Authorization
      ANONYMOUS_USER = "anonymous"

      # Permissions granted to each Core role. Permissions are the strings
      # passed to authorize(permission:) throughout the APIs. A permission
      # not listed for any role is only available to admin and service.
      VIEWER_PERMISSIONS = %w[system tlm cmd_info script_view].freeze
      OPERATOR_PERMISSIONS = (VIEWER_PERMISSIONS + %w[cmd cmd_raw tlm_set script_run script_edit]).freeze
      APPROVER_PERMISSIONS = (OPERATOR_PERMISSIONS + %w[script_approver]).freeze
      ROLE_PERMISSIONS = {
        'viewer' => VIEWER_PERMISSIONS,
        'operator' => OPERATOR_PERMISSIONS,
        'approver' => APPROVER_PERMISSIONS,
        'admin' => :all, # includes admin, system_set, superadmin
        'service' => :all, # the service password used by microservices
      }.freeze

      # Returns the roles a token is bound to (via its session), or nil if the
      # token is not valid.
      def self.roles_for_token(token)
        identity = OpenC3::AuthModel.identity(token)
        return nil unless identity

        return identity['roles']
      end

      # Whether any of the given roles grants the permission. A nil permission
      # means the caller only needs to be authenticated.
      def self.roles_permit?(roles, permission)
        return true if permission.nil?

        Array(roles).each do |role|
          permissions = ROLE_PERMISSIONS[role.to_s]
          next unless permissions
          return true if permissions == :all or permissions.include?(permission.to_s)
        end
        return false
      end

      # Re-checks a stored username against the configured users. Used when an
      # operation recorded by one user is executed later by a microservice
      # (e.g. a queued command being released) so the original operator's
      # permission is enforced at execution time, not just at submission.
      # @return [Boolean] false if the user no longer exists or lacks the permission
      def self.user_permitted?(username, permission:, scope: nil)
        roles = OpenC3::AuthModel.user_roles(username)
        return false unless roles

        return roles_permit?(roles, permission)
      end

      # Generates a one time password bound to the same identity as the
      # requesting user so it can not be used to escalate.
      def self.generate_otp(user)
        case user
        when Hash
          username = user['username']
          roles = user['roles']
          name = user['name']
        when ANONYMOUS_USER
          # Authorization disabled (tests / internal callers)
          username = ANONYMOUS_USER
          roles = []
          name = ANONYMOUS_USER
        else
          raise AuthError.new("Invalid OTP user")
        end
        raise AuthError.new("Invalid OTP user") if username.nil? or username.to_s.empty?

        return OpenC3::AuthModel.generate_session(otp: true, username: username, roles: roles, name: name)
      end

      private

      # Raises an exception if unauthorized, otherwise returns the bound user.
      # @raise [AuthError] when the scope or token is missing or the token is invalid (HTTP 401)
      # @raise [ForbiddenError] when the token's roles do not grant the permission (HTTP 403)
      # @return [Hash] {'username', 'name', 'roles'} of the authenticated user,
      #   or ANONYMOUS_USER when authorization is disabled ($openc3_authorize false)
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        raise AuthError.new("Scope is required") unless scope

        return ANONYMOUS_USER unless $openc3_authorize

        raise AuthError.new("Token is required") unless token

        identity = OpenC3::AuthModel.identity(token)
        raise AuthError.new("Token is invalid") unless identity

        unless Authorization.roles_permit?(identity['roles'], permission)
          resource = [target_name, packet_name, interface_name, router_name].compact.join(' ')
          message = "User '#{identity['username']}' with roles #{identity['roles']} is not permitted '#{permission}'"
          message << " on #{resource}" unless resource.empty?
          raise ForbiddenError.new(message)
        end
        return identity
      end

      # Returns the identity bound to the token so callers can attribute
      # actions to the real user. Returns an empty hash for an invalid token.
      def user_info(token)
        identity = OpenC3::AuthModel.identity(token)
        return {} unless identity

        return identity
      end
    end
  end
end

# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is free software; you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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

    module Authorization
      ANONYMOUS_USER = "anonymous"

      # Core role -> permission matrix. Mirrors the Enterprise built-in roles
      # (docs/guides/roles-permissions.md). Core has a single scope and no
      # per-target role definitions, so a permission applies scope wide.
      # 'approver' additionally carries script_approver because Core has no
      # custom roles to attach it to.
      ROLE_PERMISSIONS = {
        'admin' => %w(system system_set tlm cmd_info script_view admin superadmin).freeze,
        'operator' => %w(system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_edit script_run).freeze,
        'runner' => %w(system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_run).freeze,
        'viewer' => %w(system tlm cmd_info script_view).freeze,
        'approver' => %w(approve_hazardous approve_restricted approve_normal script_approver).freeze,
      }.freeze
      ROLES = ROLE_PERMISSIONS.keys.freeze

      def self.permissions_for(roles)
        Array(roles).flat_map { |role| ROLE_PERMISSIONS.fetch(role.to_s, []) }.uniq
      end

      def self.permitted?(roles, permission)
        permissions_for(roles).include?(permission.to_s)
      end

      def self.generate_otp(user)
        user = { 'username' => OpenC3::AuthModel::BUILTIN_ADMIN_USERNAME, 'roles' => OpenC3::AuthModel::BUILTIN_ADMIN_ROLES } if user == ANONYMOUS_USER
        raise AuthError.new("Invalid OTP user") unless user.is_a?(Hash) and user['username']
        return OpenC3::AuthModel.generate_session(otp: true, username: user['username'], roles: user['roles'])
      end

      private

      # Raises AuthError if the caller is not authenticated and ForbiddenError
      # if the authenticated principal lacks the requested permission.
      # @return [Hash] the principal {'username' => String, 'roles' => Array<String>}
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        raise AuthError.new("Scope is required") unless scope

        # $openc3_authorize is set by the API servers (AuthorizedApi). Microservices
        # and scripts calling the API in-process present no token and are trusted
        # the same way they were before roles existed.
        return ANONYMOUS_USER unless $openc3_authorize

        raise AuthError.new("Token is required") unless token
        user = OpenC3::AuthModel.principal(token)
        raise AuthError.new("Token is invalid") unless user

        if permission and !Authorization.permitted?(user['roles'], permission)
          resource = [target_name, packet_name, interface_name, router_name].compact.join(' ')
          resource = " on #{resource}" unless resource.empty?
          raise ForbiddenError.new("User '#{user['username']}' with roles #{user['roles'].inspect} is not permitted '#{permission}'#{resource}")
        end
        return user
      end

      def user_info(token)
        return {} unless token
        user = OpenC3::AuthModel.principal(token)
        return user || {}
      end
    end
  end
end

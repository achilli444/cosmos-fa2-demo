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

      # Permissions granted to each Core role. These mirror the Enterprise built-in
      # roles (docs/guides/roles-permissions.md) with one difference: the Core admin
      # keeps every permission because it is the single credential created at first
      # login and must still be able to operate the system on its own.
      ADMIN_PERMISSIONS = %w(superadmin admin system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_edit script_run).freeze
      OPERATOR_PERMISSIONS = %w(system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_edit script_run).freeze
      VIEWER_PERMISSIONS = %w(system tlm cmd_info script_view).freeze
      ROLE_PERMISSIONS = {
        'admin' => ADMIN_PERMISSIONS,
        'operator' => OPERATOR_PERMISSIONS,
        'viewer' => VIEWER_PERMISSIONS,
        # Internal service account (OPENC3_SERVICE_PASSWORD) used by spawned scripts
        # and queued commands: it can command and run scripts but never administer.
        'service' => OPERATOR_PERMISSIONS,
      }.freeze

      def self.generate_otp(user)
        role = user.is_a?(Hash) ? user['roles']&.first : nil
        raise AuthError.new("Invalid OTP user") unless ROLE_PERMISSIONS.key?(role)
        return OpenC3::AuthModel.generate_session(otp: true, role: role)
      end

      # Targets a role may act on, from OPENC3_<ROLE>_TARGETS (e.g. "INST,INST2").
      # @return [Array<String>, nil] upcased target names, or nil when unrestricted
      def self.role_targets(role)
        value = ENV["OPENC3_#{role.upcase}_TARGETS"]
        return nil if value.nil? or value.strip.empty?
        return value.split(',').map { |target| target.strip.upcase }.reject(&:empty?)
      end

      def self.user_for_role(role)
        { 'username' => role, 'roles' => [role] }
      end

      private

      # Raises AuthError if the caller is not authenticated and ForbiddenError if
      # the caller's role lacks the permission or the target. Returns the user
      # ({'username', 'roles'}) or ANONYMOUS_USER when authorization is not enabled,
      # i.e. for in-process calls from trusted microservices.
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        raise AuthError.new("Scope is required") unless scope
        return ANONYMOUS_USER unless $openc3_authorize

        raise AuthError.new("Token is required") unless token
        role = OpenC3::AuthModel.role(token)
        raise AuthError.new("Token is invalid") unless role

        permissions = ROLE_PERMISSIONS[role]
        raise ForbiddenError.new("Unknown role '#{role}'") unless permissions
        raise ForbiddenError.new("Permission is required") unless permission
        unless permissions.include?(permission.to_s)
          raise ForbiddenError.new("Role '#{role}' does not have permission '#{permission}'")
        end

        if target_name
          targets = Authorization.role_targets(role)
          if targets and !targets.include?(target_name.to_s.upcase)
            raise ForbiddenError.new("Role '#{role}' is not authorized for target '#{target_name}'")
          end
        end

        return Authorization.user_for_role(role)
      end

      def user_info(token)
        role = OpenC3::AuthModel.role(token, consume_otp: false)
        return {} unless role
        return Authorization.user_for_role(role)
      end
    end
  end
end

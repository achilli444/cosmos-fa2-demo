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

require 'securerandom'
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
      # Identity recorded for sessions created with the shared frontend password
      OPERATOR_USER = "operator"
      # Identity recorded for sessions created with OPENC3_SERVICE_PASSWORD
      SERVICE_USER = "service"

      # Every permission the API layer asks for. Core fails closed on anything
      # else so a new endpoint can't skip enforcement by passing a typo.
      PERMISSIONS = %w(
        system system_set tlm tlm_set cmd_info cmd_raw cmd
        script_view script_edit script_run script_approver
        approve_hazardous approve_restricted approve_normal
        admin superadmin
      ).freeze

      # Core roles. operator, runner and viewer carry the same permissions as
      # the Enterprise built-in roles of the same name. admin holds every
      # permission because Core has a single credential and nobody else to
      # hold the administrative and approval rights.
      ROLE_PERMISSIONS = {
        'admin' => PERMISSIONS,
        'operator' => %w(system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_edit script_run).freeze,
        'runner' => %w(system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_run).freeze,
        'viewer' => %w(system tlm cmd_info script_view).freeze,
      }.freeze
      DEFAULT_ROLE = 'admin'

      # Role granted to sessions created with the frontend password
      SESSION_ROLE_ENV = 'OPENC3_SESSION_ROLE'
      # Role granted to OPENC3_SERVICE_PASSWORD and the sessions it creates
      SERVICE_ROLE_ENV = 'OPENC3_SERVICE_ROLE'

      # The user stored with a new login session. The random suffix lets
      # commands and log lines be traced back to one login even though every
      # Core login shares the same password.
      # @param service [Boolean] whether the login used OPENC3_SERVICE_PASSWORD
      # @return [Hash] user to pass to AuthModel.generate_session
      def self.session_user(service: false)
        base = service ? SERVICE_USER : OPERATOR_USER
        { 'username' => "#{base}-#{SecureRandom.hex(4)}", 'service' => service }
      end

      # One-time tokens keep the identity of the session that requested them
      def self.generate_otp(user)
        raise AuthError.new("Invalid OTP user") unless user.is_a?(Hash) and user['username']

        return OpenC3::AuthModel.generate_session(otp: true, user: user.slice('username', 'service'))
      end

      # Role name configured for the given environment variable, or DEFAULT_ROLE
      def self.configured_role(env_name)
        role = ENV.fetch(env_name, '').strip
        return DEFAULT_ROLE if role.empty?

        unless ROLE_PERMISSIONS.key?(role)
          raise AuthError.new("#{env_name} '#{role}' is not one of #{ROLE_PERMISSIONS.keys.join(', ')}")
        end

        return role
      end

      # The user hash for a token, resolved from how the session was created
      # (see AuthModel.generate_session). Does not verify the token.
      # @return [Hash] with 'username', 'roles' and 'permissions'
      def self.identity(token)
        return build_user(ENV.fetch('OPENC3_MICROSERVICE_NAME', nil) || ANONYMOUS_USER, DEFAULT_ROLE) unless $openc3_authorize

        service_password = ENV.fetch('OPENC3_SERVICE_PASSWORD', nil)
        if token and service_password and service_password == token
          return build_user(SERVICE_USER, configured_role(SERVICE_ROLE_ENV))
        end

        info = OpenC3::AuthModel.session_info(token)
        return build_user(ANONYMOUS_USER, nil) unless info

        # Sessions created before this release only stored a timestamp
        username = info['username'].to_s
        username = OPERATOR_USER if username.empty?
        role = configured_role(info['service'] ? SERVICE_ROLE_ENV : SESSION_ROLE_ENV)
        user = build_user(username, role)
        user['service'] = true if info['service']
        return user
      end

      def self.build_user(username, role)
        permissions = role ? ROLE_PERMISSIONS[role] : []
        {
          'username' => username,
          'roles' => role ? [role] : [],
          'permissions' => permissions,
        }
      end

      private

      # Raises AuthError if the token is missing or invalid and ForbiddenError
      # if the caller's role does not grant the permission.
      # @return [Hash] the user hash (see Authorization.identity)
      def authorize(permission: nil, target_name: nil, packet_name: nil, interface_name: nil, router_name: nil, manual: false, scope: nil, token: nil)
        raise AuthError.new("Scope is required") unless scope
        raise ForbiddenError.new("Permission is required") if permission.nil? or permission.to_s.empty?

        permission = permission.to_s
        raise ForbiddenError.new("Unknown permission '#{permission}'") unless PERMISSIONS.include?(permission)

        if $openc3_authorize
          raise AuthError.new("Token is required") unless token

          # Resolve the identity before verifying: verifying a one-time token
          # consumes it, after which there is nothing left to look up.
          user = Authorization.identity(token)
          unless OpenC3::AuthModel.verify(token)
            raise AuthError.new("Token is invalid")
          end
        else
          user = Authorization.identity(nil)
        end

        unless user['permissions'].include?(permission)
          resource = [target_name, packet_name, interface_name, router_name].compact.join(' ')
          message = "User #{user['username']} does not have permission '#{permission}'"
          message += " for #{resource}" unless resource.empty?
          raise ForbiddenError.new(message)
        end
        return user
      end

      def user_info(token)
        return {} if token.nil? or token.to_s.empty?

        return Authorization.identity(token)
      end
    end
  end
end

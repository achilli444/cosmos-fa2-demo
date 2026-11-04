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

begin
  require 'openc3-enterprise/controllers/roles_controller'
rescue LoadError
  # Core: roles are the fixed set in OpenC3::Authorization::ROLE_PERMISSIONS.
  # They are readable so the tools can resolve a role to its permissions, but
  # cannot be created or changed (that requires Enterprise).
  class RolesController < ApplicationController
    def index
      return unless authorization('system')
      render json: OpenC3::Authorization::ROLES.map { |role| role_json(role) }
    end

    def show
      return unless authorization('system')
      permissions = OpenC3::Authorization::ROLE_PERMISSIONS[params[:id]]
      if permissions
        render json: role_json(params[:id])
      else
        head :not_found
      end
    end

    def create
      return unless authorization('admin')
      render json: { status: 'error', message: 'Roles are fixed in COSMOS Core' }, status: :not_implemented
    end
    alias update create
    alias destroy create

    private

    def role_json(role)
      {
        'name' => role,
        'permissions' => OpenC3::Authorization::ROLE_PERMISSIONS[role].map { |permission| { 'permission' => permission } },
      }
    end
  end
end

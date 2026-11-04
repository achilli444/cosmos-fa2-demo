
# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

begin
  require 'openc3-enterprise/controllers/users_controller'
rescue LoadError
  class UsersController < ApplicationController
    def active()
      render json: []
    end

    def index
      return unless authorization('admin')

      render json: OpenC3::AuthModel.users
    rescue StandardError => e
      log_error(e)
      render json: { status: 'error', message: e.message, type: e.class }, status: :internal_server_error
    end

    # Creates or replaces a named operator account (admin only)
    def create
      return unless authorization('admin')

      begin
        user = OpenC3::AuthModel.add_user(params[:username], params[:password], roles: params[:roles], targets: params[:targets])
        OpenC3::Logger.info("User '#{user['username']}' created with roles #{user['roles'].join(',')} targets #{user['targets'] ? user['targets'].join(',') : 'ALL'}", user: username())
        render json: user, status: :created
      rescue RuntimeError => e
        render json: { status: 'error', message: e.message, type: e.class }, status: :bad_request
      rescue StandardError => e
        log_error(e)
        render json: { status: 'error', message: e.message, type: e.class }, status: :internal_server_error
      end
    end

    def destroy
      return unless authorization('admin')

      begin
        if OpenC3::AuthModel.remove_user(params[:username])
          OpenC3::Logger.info("User '#{params[:username]}' removed", user: username())
          head :ok
        else
          head :not_found
        end
      rescue RuntimeError => e
        render json: { status: 'error', message: e.message, type: e.class }, status: :bad_request
      rescue StandardError => e
        log_error(e)
        render json: { status: 'error', message: e.message, type: e.class }, status: :internal_server_error
      end
    end

    def logout()
      # Require a valid token so logout is not reachable unauthenticated (CWE-306)
      return unless authorization('system')

      # Terminate only the caller's own session token (from the Authorization
      # header), not the entire global sessions store, so one user logging out
      # does not log out every other operator.
      OpenC3::AuthModel.terminate(request.headers['HTTP_AUTHORIZATION'])
      head :ok
    end
  end
end

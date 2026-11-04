
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
  # Core named-account management. Every mutation is gated on the 'admin'
  # permission and written to the audit log with the acting user.
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

    def show
      return unless authorization('admin')
      record = OpenC3::AuthModel.user(params[:id])
      if record
        record.delete('password_hash')
        render json: record
      else
        head :not_found
      end
    rescue StandardError => e
      log_error(e)
      render json: { status: 'error', message: e.message, type: e.class }, status: :internal_server_error
    end

    def create
      return unless authorization('admin')
      roles = Array(params[:roles])
      unless roles.any? and (roles - OpenC3::Authorization::ROLES).empty?
        render json: { status: 'error', message: "roles must be a non-empty subset of #{OpenC3::Authorization::ROLES}" }, status: :bad_request
        return
      end
      record = OpenC3::AuthModel.create_user(
        username: params[:username].to_s,
        password: params[:password],
        roles: roles,
        name: params[:name],
        enabled: params.key?(:enabled) ? ActiveModel::Type::Boolean.new.cast(params[:enabled]) : true,
      )
      OpenC3::Logger.info("User created: #{record['username']} roles: #{record['roles']}", scope: params[:scope], user: username())
      render json: record, status: :created
    rescue StandardError => e
      log_error(e)
      render json: { status: 'error', message: e.message, type: e.class }, status: :bad_request
    end

    def update
      return unless authorization('admin')
      roles = params.key?(:roles) ? Array(params[:roles]) : nil
      if roles and (roles.empty? or !(roles - OpenC3::Authorization::ROLES).empty?)
        render json: { status: 'error', message: "roles must be a non-empty subset of #{OpenC3::Authorization::ROLES}" }, status: :bad_request
        return
      end
      enabled = params.key?(:enabled) ? ActiveModel::Type::Boolean.new.cast(params[:enabled]) : nil
      record = OpenC3::AuthModel.update_user(params[:id], roles: roles, enabled: enabled, password: params[:password], name: params[:name])
      changes = []
      changes << "roles: #{record['roles']}" if roles
      changes << "enabled: #{record['enabled']}" unless enabled.nil?
      changes << "password changed" if params[:password]
      OpenC3::Logger.info("User updated: #{record['username']} #{changes.join(', ')}", scope: params[:scope], user: username())
      render json: record
    rescue StandardError => e
      log_error(e)
      status = e.message == "user not found" ? :not_found : :bad_request
      render json: { status: 'error', message: e.message, type: e.class }, status: status
    end

    def destroy
      return unless authorization('admin')
      OpenC3::AuthModel.delete_user(params[:id])
      OpenC3::Logger.info("User deleted: #{params[:id]}", scope: params[:scope], user: username())
      head :ok
    rescue StandardError => e
      log_error(e)
      status = e.message == "user not found" ? :not_found : :bad_request
      render json: { status: 'error', message: e.message, type: e.class }, status: status
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

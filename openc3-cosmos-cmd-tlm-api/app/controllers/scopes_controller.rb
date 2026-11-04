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

require 'openc3/utilities/process_manager'
require 'openc3/models/scope_model'

class ScopesController < ModelController
  def initialize
    @model_class = OpenC3::ScopeModel
  end

  def index
    # No authorization required
    render json: @model_class.names()
  end

  def create(update_model = false)
    return unless authorization('superadmin')
    model = @model_class.from_json(params[:json])
    if update_model
      existing = @model_class.get(name: model.name)
      model.update
      # Scopes are global so the scope is always 'DEFAULT'
      changes = existing ? model.diff(existing) : nil
      if changes.nil? || changes.any?
        audit("User #{username()} updated scope '#{model.name}': #{(changes || [params[:json]]).join(', ')}", scope: 'DEFAULT')
      else
        audit("User #{username()} updated scope '#{model.name}' (no changes)", scope: 'DEFAULT')
      end
    else
      model.create
      model.deploy(".", {})
      # Scopes are global so the scope is always 'DEFAULT'
      audit("User #{username()} created scope '#{model.name}'", scope: 'DEFAULT')
    end
    head :ok
  rescue Exception => e
    log_error(e)
    render json: { status: 'error', message: e.message }, status: :internal_server_error
  end

  def destroy
    return unless authorization('superadmin')
    # Scopes are global so the scope is always 'DEFAULT'
    result = OpenC3::ProcessManager.instance.spawn(["ruby", "/openc3/bin/openc3cli", "destroyscope", params[:id]], "scope_uninstall", params[:id], Time.now + 2.hours, scope: 'DEFAULT')
    audit("Scope destroy requested: #{params[:id]}", scope: 'DEFAULT')
    render json: result
  rescue Exception => e
    log_error(e)
    render json: { status: 'error', message: e.message }, status: :internal_server_error
  end
end

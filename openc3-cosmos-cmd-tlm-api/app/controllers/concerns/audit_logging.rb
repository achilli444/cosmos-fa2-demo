# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
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
# See GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/utilities/audit_log'

# Central audit hook for the Rails API layer. Every state-changing request
# produces a user-attributed OpenC3::Logger record:
#
# * Controllers call audit() to describe what changed (preferred).
# * The after_action writes a generic record for any POST/PUT/PATCH/DELETE
#   request whose action did not call audit(), including requests rejected
#   with 4xx, so no mutation goes unrecorded.
#
# Messages must never include passwords, tokens or request bodies.
module AuditLogging
  extend ActiveSupport::Concern

  AUDITED_HTTP_METHODS = %w(POST PUT PATCH DELETE).freeze

  included do
    after_action :audit_request
  end

  # Record a user-attributed audit message for the current request.
  # Use level: :warn for denied or failed security-relevant events.
  def audit(message, scope: params[:scope], level: :info)
    @audit_recorded = true
    OpenC3::AuditLog.record(message, scope: scope, user: audit_user, level: level)
  end

  private

  def audit_user
    username()
  rescue StandardError
    OpenC3::AuditLog::ANONYMOUS
  end

  def audit_request
    return if @audit_recorded
    return unless AUDITED_HTTP_METHODS.include?(request.request_method)

    status = response.status
    level = status >= 400 ? :warn : :info
    OpenC3::AuditLog.record("#{controller_name}##{action_name} #{request.request_method} #{request.path} -> #{status}",
                            scope: params[:scope], user: audit_user, level: level)
  end
end

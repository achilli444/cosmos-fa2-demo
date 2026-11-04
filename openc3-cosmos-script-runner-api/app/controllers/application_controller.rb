# encoding: utf-8

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

require 'openc3/utilities/authorization'

class ApplicationController < ActionController::API
  include OpenC3::Authorization

  # Audit record for state-changing actions and every denied request.
  # Controllers declare the actions that must leave a record with
  # `audit_actions create: 'Script saved', ...`; the hash value is the message
  # used when the action succeeds. Denied requests (401/403) are always logged,
  # audited or not. The user is derived from the token; the token is never logged.
  class_attribute :audited_actions, instance_writer: false, default: {}
  around_action :audit_request

  def self.audit_actions(actions)
    self.audited_actions = audited_actions.merge(actions.transform_keys(&:to_s))
  end

  private

  # Attach fields to the audit record of the current request
  def audit_detail(**fields)
    @audit_detail ||= {}
    @audit_detail.merge!(fields)
  end

  def audit_request
    yield
  rescue StandardError => e
    @audit_error = e
    raise
  ensure
    write_audit_record()
  end

  def write_audit_record
    status = @audit_error ? 500 : response.status
    denied = [401, 403].include?(status)
    return unless denied or audited_actions.key?(action_name)

    outcome = audit_outcome(status)
    name = params[:name]
    data = {
      audit: 'script-api',
      controller: controller_name,
      action: action_name,
      method: request.request_method,
      path: request.path,
      status: status,
      outcome: outcome,
    }
    data[:script] = name if name
    data[:permission] = @audit_permission if @audit_permission
    data[:target] = @audit_target if @audit_target
    data[:reason] = @audit_reason if @audit_reason
    data[:error] = @audit_error.class.name if @audit_error
    data.merge!(@audit_detail) if @audit_detail
    outcome = data[:outcome]

    label = audited_actions[action_name]
    if outcome == 'success' and label
      message = label
    else
      message = "#{controller_name}##{action_name} #{outcome}"
    end
    message += ": #{name}" if name

    options = { user: audit_user(), other: data }
    options[:scope] = params[:scope] if params[:scope]
    if outcome == 'success'
      OpenC3::Logger.info(message, **options)
    else
      OpenC3::Logger.warn(message, **options)
    end
  rescue StandardError => e
    log_error(e)
  end

  def audit_outcome(status)
    case status
    when 200..299 then 'success'
    when 401 then 'unauthorized'
    when 403 then 'forbidden'
    when 404 then 'not_found'
    when 400..499 then 'rejected'
    else 'error'
    end
  end

  def audit_user
    username()
  rescue StandardError
    'unknown'
  end

  def user_full_name()
    # For user_info see openc3/utilities/authorization and
    # openc3_enterprise/utilities/authorization
    user = user_info(request.headers['HTTP_AUTHORIZATION'])
    name = user['name']
    # COSMOS Core name (Enterprise has the actual name)
    name ||= 'Anonymous'
    return name
  end

  def username()
    # For user_info see openc3/utilities/authorization and
    # openc3_enterprise/utilities/authorization
    user = user_info(request.headers['HTTP_AUTHORIZATION'])
    username = user['username']
    # COSMOS Core username (Enterprise has the actual username)
    username ||= 'anonymous'
    return username
  end

  # Authorize and rescue the possible exceptions
  # @return [Boolean] true if authorize successful
  def authorization(permission, target_name: nil)
    @audit_permission = permission
    @audit_target = target_name
    begin
      authorize(
        permission: permission,
        target_name: target_name,
        manual: request.headers['HTTP_MANUAL'],
        scope: params[:scope],
        token: request.headers['HTTP_AUTHORIZATION'],
      )
    rescue OpenC3::AuthError => e
      @audit_reason = e.message
      render json: { status: 'error', message: e.message }, status: :unauthorized
      return false
    rescue OpenC3::ForbiddenError => e
      @audit_reason = e.message
      render json: { status: 'error', message: e.message }, status: :forbidden
      return false
    end
    return true
  end

  def sanitize_params(param_list, require_params: true, allow_forward_slash: false, allow_parent_dir: false)
    if require_params
      result = params.require(param_list)
    else
      result = []
      param_list.each do |param|
        result << params[param]
      end
    end
    result.each_with_index do |arg, index|
      if arg
        # Prevent the code scanner detects:
        # "Uncontrolled data used in path expression"
        # This method is taken directly from the Rails source:
        #   https://api.rubyonrails.org/v5.2/classes/ActiveStorage/Filename.html#method-i-sanitized
        if allow_forward_slash
          # Sometimes we have forward slashes so optionally allow those
          value = arg.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "�").strip.tr("\u{202E}%$|:;\t\r\n\\", "-")
        else
          value = arg.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "�").strip.tr("\u{202E}%$|:;/\t\r\n\\", "-")
        end
        if not allow_parent_dir
          value = value.gsub(/(\.|%2e){2}/i, "-")
        end
        if value != arg
          render json: { status: 'error', message: "Invalid #{param_list[index]}: #{arg}" }, status: :bad_request
          return false
        end
      end
    end
    return result
  end

  def log_error(e)
    if ENV['OPENC3_FULL_BACKTRACE']
      filtered_backtrace = e.backtrace
    else
      # Filter out backtrace to only application code
      filtered_backtrace = e.backtrace.select { |line| !line.include?('activesupport') && !line.include?('actionpack') && !line.include?('rspec') && !line.include?('bundler') }
    end
    logger.error("#{e.message}\n#{filtered_backtrace.join("\n")}")
  end
end

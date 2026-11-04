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
require 'openc3/utilities/logger'

class ApplicationController < ActionController::API
  include OpenC3::Authorization

  # Central audit record for every state-changing request (anything other than
  # GET / HEAD / OPTIONS). Each record carries the acting user, the controller
  # action, the resource identifiers, the scope and the outcome so that plugin,
  # scope, target, trigger and reaction changes are attributable from the
  # openc3_log_messages stream even when the controller itself logs nothing.
  # Controllers that already log every request with the user (ApiController)
  # opt out with skip_after_action :audit_log.
  after_action :audit_log, if: :audit_request?

  AUDIT_RESOURCE_PARAMS = %w(id name group key target screen notebook object_id new_name)
  AUDIT_VALUE_MAX_LENGTH = 200
  AUDIT_SCOPE_REGEX = /\A[A-Za-z0-9_-]+\z/

  private

  def audit_request?
    !(request.get? || request.head? || request.options?)
  end

  def audit_log
    user = audit_user()
    status = response.status
    outcome = audit_outcome(status)
    resource = audit_resource()
    scope = audit_scope()
    message = "Audit: #{user} #{request.method} #{request.path} #{controller_path}##{action_name}"
    message += " #{resource}" unless resource.empty?
    message += " scope=#{scope} => #{outcome} (#{status})"
    other = {
      audit_controller: controller_path,
      audit_action: action_name,
      audit_method: request.method,
      audit_path: request.path,
      audit_resource: resource,
      audit_status: status,
      audit_outcome: outcome,
    }
    OpenC3::Logger.info(message, scope: scope, user: user, type: OpenC3::Logger::LOG, other: other)
  rescue StandardError => e
    # The audit record must never break the response
    log_error(e)
  end

  def audit_user
    username()
  rescue StandardError
    'unknown'
  end

  def audit_outcome(status)
    if status < 400
      'success'
    elsif status == 401 || status == 403
      'denied'
    else
      'failure'
    end
  end

  # Only identifiers are recorded, never request bodies (passwords, secrets, plugin
  # variables and file contents must not land in the log stream)
  def audit_resource
    request.params.slice(*AUDIT_RESOURCE_PARAMS).map do |key, value|
      value = value.to_s
      value = "#{value[0, AUDIT_VALUE_MAX_LENGTH]}..." if value.length > AUDIT_VALUE_MAX_LENGTH
      "#{key}=#{value}"
    end.join(' ')
  end

  # Scope is only used to pick the log topic so reject anything but a plain name
  def audit_scope
    scope = params[:scope].to_s
    return scope if scope.match?(AUDIT_SCOPE_REGEX)

    'DEFAULT'
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
  # @return [Boolean or User] User if authorize successful
  def authorization(permission, target_name: nil, packet_name: nil, perform_render: true)
    begin
      return authorize(
        permission: permission,
        target_name: target_name,
        packet_name: packet_name,
        manual: request.headers['HTTP_MANUAL'],
        scope: params[:scope],
        token: request.headers['HTTP_AUTHORIZATION'],
      )
    rescue OpenC3::AuthError => e
      render json: { status: 'error', message: e.message }, status: :unauthorized if perform_render
      return false
    rescue OpenC3::ForbiddenError => e
      render json: { status: 'error', message: e.message }, status: :forbidden if perform_render
      return false
    end
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

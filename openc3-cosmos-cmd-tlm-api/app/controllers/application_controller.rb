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

  private

  # Identifies the client making the request, used to scope bad attempt
  # counters per client and to tie audit records to a source address. A
  # global counter allows any unauthenticated client to lock out every
  # operator by sending MAX_BAD_ATTEMPTS bad passwords, so everything that
  # counts bad attempts must be namespaced by this value.
  #
  # This uses Rails request.remote_ip which honors X-Forwarded-For. COSMOS runs
  # behind traefik, which discards any client supplied X-Forwarded-* headers and
  # sets them from the real connection, so a client can't choose its own bucket.
  # See the forwardedHeaders comments in openc3-traefik/traefik.yaml: if traefik
  # is configured to trust a proxy that doesn't set X-Forwarded-For, every
  # client collapses into that proxy's bucket.
  def client_id
    ip = begin
      request.remote_ip
    rescue StandardError
      nil
    end
    ip ||= request.remote_addr
    # Only allow ip address characters in the key and bound the length so the
    # attacker controlled header can't be used to build arbitrary Redis keys
    ip = ip.to_s.gsub(/[^0-9a-fA-F:.]/, '')[0, 45]
    return ip.empty? ? 'unknown' : ip
  end

  # Writes a structured audit record (OpenC3::Logger type 'audit') for a
  # security relevant event on this request: client address, endpoint and the
  # given outcome fields. Callers must never pass a password or token.
  def audit(message, level: :info, user: nil, **fields)
    other = { client_id: client_id, endpoint: "#{controller_name}##{action_name}" }.merge(fields)
    OpenC3::Logger.public_send(level, message, user: user, type: OpenC3::Logger::AUDIT, other: other)
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

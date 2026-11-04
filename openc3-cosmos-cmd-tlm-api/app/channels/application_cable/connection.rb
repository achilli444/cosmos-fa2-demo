# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/utilities/authorization'

module ApplicationCable
  class Connection < ActionCable::Connection::Base
    include OpenC3::Authorization

    identified_by :uuid
    identified_by :scope
    # AnyCable is stateless between commands — only `identified_by` values
    # are serialized and restored across subscribe/perform/unsubscribe calls.
    # A plain instance variable set in `connect` would be lost by the time
    # a channel's `subscribed` runs in a separate command.
    identified_by :url_authenticated

    # Legacy clients put the token on the cable URL (`?authorization=<token>`).
    # URLs end up in browser history and proxy access logs, so that path is
    # rejected unless an operator opts in. Current clients authenticate per
    # subscription via params[:token] (see ApplicationCable::Channel).
    URL_AUTH_ENV = 'OPENC3_ALLOW_WEBSOCKET_URL_AUTH'

    def connect
      self.uuid = SecureRandom.uuid
      self.scope = request.query_parameters[:scope]
      self.url_authenticated = false
      token = request.query_parameters[:authorization]
      return unless token

      unless self.class.url_auth_allowed?
        logger.warn("Rejected WebSocket connection: token on the URL query string is disabled (set #{URL_AUTH_ENV}=true to allow the legacy path)")
        reject_unauthorized_connection
      end
      authorization('system', token)
      self.url_authenticated = true
    end

    def self.url_auth_allowed?
      %w[1 true].include?(ENV.fetch(URL_AUTH_ENV, '').strip.downcase)
    end

    def authorization(permission, token)
      begin
        # The service password is only for internal REST calls and is never a
        # valid WebSocket credential.
        raise OpenC3::AuthError.new("Service password not accepted") if OpenC3::AuthModel.service_password?(token)

        authorize(
          permission: permission,
          scope: request.query_parameters[:scope],
          token: token,
        )
      rescue OpenC3::AuthError, OpenC3::ForbiddenError
        reject_unauthorized_connection()
      end
      true
    end
  end
end

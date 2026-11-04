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

require 'openc3/utilities/logger'

module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :uuid
    identified_by :scope

    def connect
      # Bearer tokens are never accepted on the WebSocket URL: query strings
      # land in browser history and reverse-proxy access logs. A client that
      # still sends one is refused so the leak is surfaced rather than silently
      # tolerated. Authentication happens per subscription via params[:token]
      # (see ApplicationCable::Channel#authenticate_subscription!), which
      # travels in the WebSocket frame body.
      if request.query_parameters.key?(:authorization)
        OpenC3::Logger.warn(
          "Rejected WebSocket connection: authorization token must not be sent in the URL query string",
          scope: request.query_parameters[:scope],
        )
        reject_unauthorized_connection
      end
      self.uuid = SecureRandom.uuid
      self.scope = request.query_parameters[:scope]
    end
  end
end

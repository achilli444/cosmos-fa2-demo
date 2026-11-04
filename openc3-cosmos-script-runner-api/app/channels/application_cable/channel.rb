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
  class Channel < ActionCable::Channel::Base
    include OpenC3::Authorization

    before_subscribe :authenticate_subscription!

    private

    # Every subscription authenticates with the token supplied on its channel
    # params. This is the only accepted path: tokens on the WebSocket URL are
    # refused by ApplicationCable::Connection so they stay out of browser
    # history and proxy logs. If the token is missing or invalid, the
    # subscription is rejected before `subscribed` runs.
    def authenticate_subscription!
      token = params[:token]
      if token
        begin
          authorize(permission: 'script_view', scope: connection.scope, token: token)
          return
        rescue OpenC3::AuthError, OpenC3::ForbiddenError
          # fall through to reject
        end
      end
      reject
      throw :abort
    end
  end
end

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

class AllScriptsChannel < ApplicationCable::Channel
  # Script start/complete events are published per scope (see
  # running_script_anycable_publish callers), so a subscriber only receives the
  # activity of the scope its token was authorized for.
  before_subscribe :authorize_scope!

  def subscribed
    # Defensive: if the auth before_subscribe callback rejected us, skip work.
    return if subscription_rejected?
    stream_from "script-api:all-scripts-channel:#{connection.scope}"
  end

  private

  def authorize_scope!
    return unless connection.scope.to_s.strip.empty?

    reject
    throw :abort
  end
end

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

require 'openc3/utilities/logger'

module OpenC3
  # Central audit hook. Every state-changing or security-relevant operation
  # records a user-attributed message through OpenC3::Logger so it can be
  # traced back to an actor. The Rails APIs reach this through the
  # AuditLogging controller concern; the OpenC3::Api modules call it directly
  # with the user returned by authorize().
  module AuditLog
    ANONYMOUS = 'anonymous'

    # authorize() returns a user Hash in Enterprise and the String
    # Authorization::ANONYMOUS_USER in Core. Normalize either to a username.
    def self.username(user)
      case user
      when Hash
        name = user['username'] || user[:username]
        name.nil? || name.to_s.empty? ? ANONYMOUS : name.to_s
      when String
        user.empty? ? ANONYMOUS : user
      else
        ANONYMOUS
      end
    end

    # @param message [String] What happened (never include passwords or tokens)
    # @param scope [String] Scope the action applies to
    # @param user [Hash|String|nil] Actor as returned by authorize() or a username
    # @param level [Symbol] :info for successful actions, :warn for denied or failed ones
    def self.record(message, scope:, user:, level: :info)
      Logger.public_send(level, message, scope: scope, user: username(user))
    end
  end
end

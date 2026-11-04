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

module OpenC3
  # Governs the operator safety-check bypass API variants: cmd_no_range_check,
  # cmd_no_hazardous_check, cmd_no_checks and their cmd_raw_* equivalents.
  #
  # A bypass is authorized with the distinct PERMISSION (in addition to 'cmd')
  # and is only dispatched by the interface when the deployment sets ENV_VAR
  # or the scope routes it through critical command approval.
  module CmdBypass
    PERMISSION = 'cmd_bypass'
    ENV_VAR = 'OPENC3_ALLOW_CMD_BYPASS'
    DISABLED_VALUES = %w(0 FALSE NO OFF)

    def self.requested?(range_check:, hazardous_check:)
      range_check == false or hazardous_check == false
    end

    def self.allowed?
      value = ENV[ENV_VAR].to_s.strip
      return false if value.empty?

      return !DISABLED_VALUES.include?(value.upcase)
    end

    def self.rejection_message(cmd_string)
      "#{cmd_string} bypasses command safety checks and is not permitted: " \
        "set #{ENV_VAR} or enable critical commanding for the scope"
    end
  end
end

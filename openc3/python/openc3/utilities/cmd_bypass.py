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

"""Governs the operator safety-check bypass API variants: cmd_no_range_check,
cmd_no_hazardous_check, cmd_no_checks and their cmd_raw_* equivalents.

A bypass is authorized with the distinct CMD_BYPASS_PERMISSION (in addition to
'cmd') and is only dispatched by the interface when the deployment sets
CMD_BYPASS_ENV_VAR or the scope routes it through critical command approval.
"""

import os


CMD_BYPASS_PERMISSION = "cmd_bypass"
CMD_BYPASS_ENV_VAR = "OPENC3_ALLOW_CMD_BYPASS"
_DISABLED_VALUES = ("0", "FALSE", "NO", "OFF")


def cmd_bypass_requested(range_check, hazardous_check):
    return range_check is False or hazardous_check is False


def cmd_bypass_allowed():
    value = os.environ.get(CMD_BYPASS_ENV_VAR, "").strip()
    if not value:
        return False
    return value.upper() not in _DISABLED_VALUES


def cmd_bypass_rejection_message(cmd_string):
    return (
        f"{cmd_string} bypasses command safety checks and is not permitted: "
        f"set {CMD_BYPASS_ENV_VAR} or enable critical commanding for the scope"
    )

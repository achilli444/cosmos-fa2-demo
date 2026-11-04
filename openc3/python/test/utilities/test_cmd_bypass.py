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

import os
import unittest
from unittest.mock import patch

from openc3.utilities.cmd_bypass import (
    CMD_BYPASS_ENV_VAR,
    CMD_BYPASS_PERMISSION,
    cmd_bypass_allowed,
    cmd_bypass_rejection_message,
    cmd_bypass_requested,
)


class TestCmdBypass(unittest.TestCase):
    def test_permission_is_distinct_from_cmd(self):
        self.assertEqual(CMD_BYPASS_PERMISSION, "cmd_bypass")
        self.assertNotEqual(CMD_BYPASS_PERMISSION, "cmd")

    def test_requested_when_either_check_is_disabled(self):
        self.assertTrue(cmd_bypass_requested(False, True))
        self.assertTrue(cmd_bypass_requested(True, False))
        self.assertTrue(cmd_bypass_requested(False, False))

    def test_not_requested_for_normal_or_raw_buffer_commands(self):
        self.assertFalse(cmd_bypass_requested(True, True))
        self.assertFalse(cmd_bypass_requested(True, None))

    def test_allowed_defaults_to_false(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(CMD_BYPASS_ENV_VAR, None)
            self.assertFalse(cmd_bypass_allowed())
            os.environ[CMD_BYPASS_ENV_VAR] = "  "
            self.assertFalse(cmd_bypass_allowed())

    def test_allowed_treats_falsey_values_as_disabled(self):
        for value in ["0", "false", "FALSE", "no", "Off"]:
            with patch.dict(os.environ, {CMD_BYPASS_ENV_VAR: value}):
                self.assertFalse(cmd_bypass_allowed(), f"expected {value} to disable")

    def test_allowed_for_other_values(self):
        for value in ["1", "true", "TRUE", "yes"]:
            with patch.dict(os.environ, {CMD_BYPASS_ENV_VAR: value}):
                self.assertTrue(cmd_bypass_allowed(), f"expected {value} to enable")

    def test_rejection_message_names_command_and_remedies(self):
        message = cmd_bypass_rejection_message('cmd_no_checks("INST ABORT")')
        self.assertIn('cmd_no_checks("INST ABORT")', message)
        self.assertIn(CMD_BYPASS_ENV_VAR, message)
        self.assertIn("critical commanding", message)

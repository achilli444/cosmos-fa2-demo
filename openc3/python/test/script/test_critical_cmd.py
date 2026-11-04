# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

import unittest
from unittest.mock import patch

import openc3.script
from test.test_helper import *


class TestPromptForCriticalCmd(unittest.TestCase):
    def setUp(self):
        mock_redis(self)

    def call(self):
        openc3.script.prompt_for_critical_cmd("uuid-1234", "operator", "INST", "CLEAR", {}, 'cmd("INST CLEAR")')

    @patch("openc3.script.time.sleep")
    def test_polls_through_pending_until_approved(self, sleep):
        with patch("openc3.script.critical_cmd_status", side_effect=["PENDING", "PENDING", "APPROVED"]) as status:
            self.call()
        self.assertEqual(status.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        sleep.assert_called_with(0.1)

    @patch("openc3.script.time.sleep")
    def test_returns_immediately_when_approved(self, sleep):
        with patch("openc3.script.critical_cmd_status", return_value="APPROVED"):
            self.call()
        sleep.assert_not_called()

    @patch("openc3.script.time.sleep")
    def test_raises_when_rejected_after_pending(self, sleep):
        with (
            patch("openc3.script.critical_cmd_status", side_effect=["PENDING", "REJECTED"]),
            self.assertRaisesRegex(RuntimeError, "Critical command rejected"),
        ):
            self.call()
        sleep.assert_called_once_with(0.1)

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

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

import unittest
from unittest.mock import Mock, patch

from openc3.script.queue import queue_exec


class TestQueue(unittest.TestCase):
    def setUp(self):
        self.mock_response = Mock()
        self.mock_response.status_code = 200
        self.mock_response.text = '{"id": 1.0}'

    @patch("openc3.script.queue.API_SERVER")
    def test_queue_exec_does_not_confirm_hazardous_by_default(self, mock_api_server):
        mock_api_server.request.return_value = self.mock_response
        result = queue_exec("TEST")
        mock_api_server.request.assert_called_with(
            "post", "/openc3-api/queues/TEST/exec_command", scope="DEFAULT", data={}, json=True
        )
        self.assertEqual(result, {"id": 1.0})

    @patch("openc3.script.queue.API_SERVER")
    def test_queue_exec_sends_confirm_hazardous_when_requested(self, mock_api_server):
        mock_api_server.request.return_value = self.mock_response
        queue_exec("TEST", 5, confirm_hazardous=True)
        mock_api_server.request.assert_called_with(
            "post",
            "/openc3-api/queues/TEST/exec_command",
            scope="DEFAULT",
            data={"id": 5, "confirm_hazardous": True},
            json=True,
        )

    @patch("openc3.script.queue.API_SERVER")
    def test_queue_exec_raises_on_hazardous_refusal(self, mock_api_server):
        self.mock_response.status_code = 409
        self.mock_response.text = (
            '{"status":"error","type":"HazardousError",'
            '"message":"INST CLEAR with {} is Hazardous due to \'Clears counters\'."}'
        )
        mock_api_server.request.return_value = self.mock_response
        with self.assertRaisesRegex(RuntimeError, "Failed to exec command due to INST CLEAR .* is Hazardous"):
            queue_exec("TEST")

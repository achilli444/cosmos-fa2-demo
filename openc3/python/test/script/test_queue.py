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
from unittest.mock import Mock, patch

from openc3.script.queue import queue_exec


HAZARDOUS_BODY = (
    '{"status":"error","type":"HazardousError","hazardous":true,"message":"INST CLEAR is Hazardous",'
    '"hazardous_description":"Clears counters","target_name":"INST","cmd_name":"CLEAR","id":1.0}'
)
SUCCESS_BODY = '{"username":"user","target_name":"INST","cmd_name":"CLEAR","id":1.0}'


def _response(status_code, text):
    response = Mock()
    response.status_code = status_code
    response.text = text
    return response


class TestQueueExec(unittest.TestCase):
    @patch("openc3.script.prompt_for_hazardous")
    @patch("openc3.script.queue.API_SERVER")
    def test_executes_non_hazardous_command_without_prompting(self, mock_api_server, mock_prompt):
        mock_api_server.request.return_value = _response(200, SUCCESS_BODY)
        result = queue_exec("TEST", 1)
        self.assertEqual(result["cmd_name"], "CLEAR")
        mock_prompt.assert_not_called()
        mock_api_server.request.assert_called_once_with(
            "post", "/openc3-api/queues/TEST/exec_command", scope="DEFAULT", data={"id": 1}, json=True
        )

    @patch("openc3.script.prompt_for_hazardous")
    @patch("openc3.script.queue.API_SERVER")
    def test_prompts_and_resends_hazardous_command_with_confirmation(self, mock_api_server, mock_prompt):
        mock_api_server.request.side_effect = [_response(409, HAZARDOUS_BODY), _response(200, SUCCESS_BODY)]
        mock_prompt.return_value = True
        result = queue_exec("TEST")
        self.assertEqual(result["cmd_name"], "CLEAR")
        mock_prompt.assert_called_once_with("INST", "CLEAR", "Clears counters")
        self.assertEqual(mock_api_server.request.call_count, 2)
        self.assertEqual(mock_api_server.request.call_args_list[0].kwargs["data"], {})
        self.assertEqual(mock_api_server.request.call_args_list[1].kwargs["data"], {"hazardous_confirmed": True})

    @patch("openc3.script.prompt_for_hazardous")
    @patch("openc3.script.queue.API_SERVER")
    def test_does_not_resend_hazardous_command_when_declined(self, mock_api_server, mock_prompt):
        mock_api_server.request.side_effect = [_response(409, HAZARDOUS_BODY), _response(200, SUCCESS_BODY)]
        mock_prompt.return_value = False
        with self.assertRaisesRegex(
            RuntimeError, "Hazardous command INST CLEAR was not confirmed and remains in queue TEST"
        ):
            queue_exec("TEST")
        self.assertEqual(mock_api_server.request.call_count, 1)

    @patch("openc3.script.queue.API_SERVER")
    def test_raises_other_errors_as_before(self, mock_api_server):
        mock_api_server.request.return_value = _response(
            404, '{"status":"error","message":"No commands in queue TEST"}'
        )
        with self.assertRaisesRegex(RuntimeError, "Failed to exec command due to No commands in queue TEST"):
            queue_exec("TEST")

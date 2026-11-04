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

import unittest
from unittest.mock import Mock, patch

from openc3.io.json_drb_object import JsonDRbObject
from openc3.utilities.authentication import OpenC3Authentication
from test.test_helper import *


def _auth_error_body():
    return {
        "jsonrpc": "2.0",
        "id": 0,
        "error": {
            "code": -32500,
            "message": "Token is invalid",
            "data": {"class": "AuthError", "message": "Token is invalid"},
        },
    }


def _ok_body():
    return {"jsonrpc": "2.0", "id": 0, "result": 42}


def _response(status_code, body):
    resp = Mock()
    resp.status_code = status_code
    resp.headers = {}
    resp.text = ""
    resp.json.return_value = body
    return resp


@patch("openc3.io.json_api_object.Session")
@patch("openc3.utilities.authentication.Session")
@patch("openc3.utilities.authentication.OPENC3_API_PASSWORD", "test_password")
class TestJsonDRbObjectReauth(unittest.TestCase):
    def _setup(self, auth_session_class, api_session_class):
        self.auth_session = Mock()
        self.auth_response = Mock()
        self.auth_response.text = "first_token"
        self.auth_session.post.return_value = self.auth_response
        auth_session_class.return_value = self.auth_session
        self.http = Mock()
        api_session_class.return_value = self.http
        return JsonDRbObject("http://localhost:2901", authentication=OpenC3Authentication())

    def test_reauthenticates_once_and_retries_on_401(self, auth_session_class, api_session_class):
        drb = self._setup(auth_session_class, api_session_class)
        tokens = []

        def post(**kwargs):
            tokens.append(kwargs["headers"]["Authorization"])
            if len(tokens) == 1:
                self.auth_response.text = "fresh_token"
                return _response(401, _auth_error_body())
            return _response(200, _ok_body())

        self.http.post.side_effect = post
        self.assertEqual(drb.tlm("INST HEALTH_STATUS TEMP1", scope="DEFAULT"), 42)
        self.assertEqual(tokens, ["first_token", "fresh_token"])
        self.assertEqual(self.auth_session.post.call_count, 2)

    def test_raises_when_reauthentication_does_not_help(self, auth_session_class, api_session_class):
        drb = self._setup(auth_session_class, api_session_class)
        self.http.post.return_value = _response(401, _auth_error_body())
        with self.assertRaisesRegex(RuntimeError, "Token is invalid"):
            drb.tlm("INST HEALTH_STATUS TEMP1", scope="DEFAULT")
        self.assertEqual(self.http.post.call_count, 2)
        self.assertEqual(self.auth_session.post.call_count, 2)

    def test_does_not_reauthenticate_with_explicit_token(self, auth_session_class, api_session_class):
        drb = self._setup(auth_session_class, api_session_class)
        self.http.post.return_value = _response(401, _auth_error_body())
        with self.assertRaises(RuntimeError):
            drb.tlm("INST HEALTH_STATUS TEMP1", scope="DEFAULT", token="explicit")
        self.assertEqual(self.http.post.call_count, 1)
        self.assertEqual(self.auth_session.post.call_count, 1)

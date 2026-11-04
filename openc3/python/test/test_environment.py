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

import openc3.environment as environment
from openc3.environment import OpenC3PlaintextApiError, resolve_api_schema
from openc3.script.server_proxy import ApiServerProxy, ScriptServerProxy
from openc3.script.web_socket_api import CmdTlmWebSocketApi, ScriptWebSocketApi
from openc3.utilities.authentication import OpenC3Authentication


VARS = ("OPENC3_API_SCHEMA", "OPENC3_SCRIPT_API_SCHEMA", "OPENC3_ALLOW_PLAINTEXT_API")


class TestResolveApiSchema(unittest.TestCase):
    def setUp(self):
        self.saved = {var: os.environ.get(var) for var in VARS}
        for var in VARS:
            os.environ.pop(var, None)
        environment._plaintext_warned.clear()

    def tearDown(self):
        for var, value in self.saved.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value

    def test_defaults_to_https(self):
        self.assertEqual(resolve_api_schema("OPENC3_API_SCHEMA"), "https")
        os.environ["OPENC3_API_SCHEMA"] = "  "
        self.assertEqual(resolve_api_schema("OPENC3_API_SCHEMA"), "https")

    def test_accepts_secure_schemes(self):
        os.environ["OPENC3_API_SCHEMA"] = "HTTPS"
        self.assertEqual(resolve_api_schema("OPENC3_API_SCHEMA"), "https")
        os.environ["OPENC3_SCRIPT_API_SCHEMA"] = "wss"
        self.assertEqual(resolve_api_schema("OPENC3_SCRIPT_API_SCHEMA"), "wss")

    def test_refuses_http_without_override(self):
        os.environ["OPENC3_API_SCHEMA"] = "http"
        with self.assertRaisesRegex(OpenC3PlaintextApiError, "OPENC3_API_SCHEMA=http.*OPENC3_ALLOW_PLAINTEXT_API"):
            resolve_api_schema("OPENC3_API_SCHEMA")
        os.environ["OPENC3_ALLOW_PLAINTEXT_API"] = "false"
        with self.assertRaises(OpenC3PlaintextApiError):
            resolve_api_schema("OPENC3_API_SCHEMA")

    @patch("builtins.print")
    def test_allows_http_with_override_and_warns_once(self, mock_print):
        os.environ["OPENC3_API_SCHEMA"] = "http"
        os.environ["OPENC3_ALLOW_PLAINTEXT_API"] = "true"
        self.assertEqual(resolve_api_schema("OPENC3_API_SCHEMA"), "http")
        self.assertEqual(resolve_api_schema("OPENC3_API_SCHEMA"), "http")
        mock_print.assert_called_once()
        self.assertIn("sends credentials and data unencrypted", mock_print.call_args[0][0])

    def test_url_builders_default_to_https(self):
        self.assertEqual(ApiServerProxy.generate_url(None), "https://openc3-cosmos-cmd-tlm-api:2901")
        self.assertEqual(ScriptServerProxy.generate_url(None), "https://openc3-cosmos-script-runner-api:2902")
        self.assertEqual(CmdTlmWebSocketApi.generate_url(None), "wss://openc3-cosmos-cmd-tlm-api:3901/openc3-api/cable")
        self.assertEqual(
            ScriptWebSocketApi.generate_url(None), "wss://openc3-cosmos-script-runner-api:3902/script-api/cable"
        )
        auth = OpenC3Authentication.__new__(OpenC3Authentication)
        auth.service = False
        self.assertEqual(auth._generate_auth_url(), "https://openc3-cosmos-cmd-tlm-api:2901/openc3-api/auth/verify")

    def test_url_builders_refuse_http_without_override(self):
        os.environ["OPENC3_API_SCHEMA"] = "http"
        os.environ["OPENC3_SCRIPT_API_SCHEMA"] = "http"
        with self.assertRaises(OpenC3PlaintextApiError):
            ApiServerProxy.generate_url(None)
        with self.assertRaises(OpenC3PlaintextApiError):
            CmdTlmWebSocketApi.generate_url(None)
        with self.assertRaises(OpenC3PlaintextApiError):
            ScriptWebSocketApi.generate_url(None)
        auth = OpenC3Authentication.__new__(OpenC3Authentication)
        auth.service = False
        with self.assertRaises(OpenC3PlaintextApiError):
            auth._generate_auth_url()

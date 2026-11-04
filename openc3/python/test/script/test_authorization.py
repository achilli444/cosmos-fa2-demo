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

import json
import logging
import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch

from openc3.script import authorization


class TestCosmosKeycloakAuthorizationLogging(unittest.TestCase):
    def _response(self, payload):
        resp = MagicMock()
        resp.status_code = 200
        resp.elapsed = timedelta(seconds=0.1)
        resp.content = json.dumps(payload).encode()
        resp.json.return_value = payload
        resp.__str__.return_value = "<Response [200]>"
        return resp

    def _auth(self):
        with patch.object(authorization.CosmosKeycloakAuthorization, "_make_token_request"):
            auth = authorization.CosmosKeycloakAuthorization(schema="http", hostname="localhost", port=2900)
        auth.refresh_token = "REFRESH_TOKEN_VALUE"
        return auth

    def test_token_request_debug_log_redacts_tokens(self):
        payload = {
            "access_token": "ACCESS_TOKEN_VALUE",
            "expires_in": 600,
            "refresh_expires_in": 1800,
            "refresh_token": "REFRESH_TOKEN_VALUE",
            "id_token": "ID_TOKEN_VALUE",
        }
        auth = self._auth()
        with (
            patch.object(authorization, "OPENC3_API_USER", "bob"),
            patch.object(authorization, "OPENC3_API_PASSWORD", "PASSWORD_VALUE"),
            patch.object(authorization.requests, "post", return_value=self._response(payload)),
            self.assertLogs(authorization.LOGGER, level=logging.DEBUG) as logs,
        ):
            auth._make_token_request()
        output = "\n".join(logs.output)
        self.assertIn("total_seconds", output)
        self.assertIn('"expires_in": 600', output)
        for secret in ["ACCESS_TOKEN_VALUE", "REFRESH_TOKEN_VALUE", "ID_TOKEN_VALUE", "PASSWORD_VALUE"]:
            self.assertNotIn(secret, output)

    def test_refresh_request_debug_log_redacts_tokens(self):
        payload = {"access_token": "ACCESS_TOKEN_VALUE", "expires_in": 600, "refresh_token": "NEW_REFRESH_TOKEN"}
        auth = self._auth()
        with (
            patch.object(authorization.requests, "post", return_value=self._response(payload)),
            self.assertLogs(authorization.LOGGER, level=logging.DEBUG) as logs,
        ):
            auth._make_refresh_request()
        output = "\n".join(logs.output)
        self.assertIn("calling with", output)
        self.assertIn("grant_type=refresh_token", output)
        for secret in ["REFRESH_TOKEN_VALUE", "ACCESS_TOKEN_VALUE", "NEW_REFRESH_TOKEN"]:
            self.assertNotIn(secret, output)

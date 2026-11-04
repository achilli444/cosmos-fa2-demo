# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

import json
import logging
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

from openc3.__version__ import __title__
from openc3.script.authorization import CosmosKeycloakAuthorization
from test.test_helper import *


TOKEN_RESPONSE = {
    "access_token": "access_token_123",
    "expires_in": 600,
    "refresh_expires_in": 1800,
    "refresh_token": "refresh_token_123",
    "id_token": "id_token_123",
    "token_type": "bearer",
}

SECRETS = ("p@ss&word", "access_token_123", "refresh_token_123", "id_token_123", "offline_refresh_token")


def mock_token_response():
    resp = Mock()
    resp.status_code = 200
    resp.text = json.dumps(TOKEN_RESPONSE)
    resp.content = resp.text.encode()
    resp.elapsed = timedelta(milliseconds=5)
    resp.json = Mock(return_value=TOKEN_RESPONSE)
    return resp


@patch("openc3.script.authorization.OPENC3_KEYCLOAK_URL", "http://test-keycloak.local")
@patch("openc3.script.authorization.OPENC3_KEYCLOAK_REALM", "openc3")
@patch("openc3.script.authorization.OPENC3_API_CLIENT", "api")
class TestCosmosKeycloakAuthorization(unittest.TestCase):
    @patch("openc3.script.authorization.OPENC3_API_USER", "testuser")
    @patch("openc3.script.authorization.OPENC3_API_PASSWORD", "p@ss&word")
    @patch("openc3.script.authorization.requests.post")
    def test_password_grant_sends_form_dict_and_masks_debug_logs(self, mock_post):
        """Password grant posts a dict (URL-encoded by requests) and never logs secrets"""
        mock_post.return_value = mock_token_response()
        auth = CosmosKeycloakAuthorization()

        with self.assertLogs(__title__, level=logging.DEBUG) as logs:
            self.assertEqual(auth.get(), "Bearer access_token_123")

        kwargs = mock_post.call_args.kwargs
        self.assertEqual(kwargs["url"], "http://test-keycloak.local/realms/openc3/protocol/openid-connect/token")
        self.assertEqual(
            kwargs["data"],
            {
                "username": "testuser",
                "password": "p@ss&word",
                "client_id": "api",
                "grant_type": "password",
                "scope": "openid",
            },
        )
        self.assertEqual(auth.refresh_token, "refresh_token_123")

        output = "\n".join(logs.output)
        self.assertIn("'password': '***'", output)
        self.assertIn("'access_token': '***'", output)
        self.assertIn("'refresh_token': '***'", output)
        self.assertIn("'id_token': '***'", output)
        self.assertIn("'username': 'testuser'", output)
        for secret in SECRETS:
            self.assertNotIn(secret, output)

    @patch("openc3.script.authorization.OPENC3_API_USER", None)
    @patch("openc3.script.authorization.OPENC3_API_PASSWORD", None)
    @patch("openc3.script.authorization.requests.post")
    def test_refresh_grant_sends_form_dict_and_masks_debug_logs(self, mock_post):
        """Refresh grant posts a dict and never logs the refresh token or the response tokens"""
        mock_post.return_value = mock_token_response()
        auth = CosmosKeycloakAuthorization()
        auth.refresh_token = "offline_refresh_token"

        with self.assertLogs(__title__, level=logging.DEBUG) as logs:
            auth._refresh_token()

        kwargs = mock_post.call_args.kwargs
        self.assertEqual(
            kwargs["data"],
            {"client_id": "api", "grant_type": "refresh_token", "refresh_token": "offline_refresh_token"},
        )
        self.assertEqual(auth.token, "access_token_123")
        self.assertEqual(auth.refresh_token, "refresh_token_123")

        output = "\n".join(logs.output)
        self.assertIn("'refresh_token': '***'", output)
        self.assertIn("'access_token': '***'", output)
        for secret in SECRETS:
            self.assertNotIn(secret, output)

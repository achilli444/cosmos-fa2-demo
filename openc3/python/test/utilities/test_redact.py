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
import unittest

from openc3.utilities.redact import REDACTED, redact, sensitive_key


class TestRedact(unittest.TestCase):
    def test_sensitive_key_flags_credential_names(self):
        for key in [
            "password",
            "PASSWD",
            "passphrase",
            "store_api_key",
            "apiKey",
            "secret",
            "refresh_token",
            "access_token",
            "Authorization",
            "Cookie",
            "credentials",
            "private_key",
            "signing_key",
        ]:
            self.assertTrue(sensitive_key(key), key)

    def test_sensitive_key_ignores_ordinary_names(self):
        for key in ["username", "theme", "keyboard", "news_feed", "scope", "grant_type", "client_id"]:
            self.assertFalse(sensitive_key(key), key)

    def test_redacts_dict_values_recursively(self):
        data = {
            "store_api_key": "abc",
            "theme": "dark",
            "nested": {"password": "pw", "ok": 1},
            "list": [{"token": "t"}],
        }
        self.assertEqual(
            redact(data),
            {
                "store_api_key": REDACTED,
                "theme": "dark",
                "nested": {"password": REDACTED, "ok": 1},
                "list": [{"token": REDACTED}],
            },
        )
        self.assertEqual(data["store_api_key"], "abc")

    def test_redacts_json_strings_and_bytes(self):
        body = b'{"access_token":"AT","expires_in":600,"refresh_token":"RT","id_token":"IDT"}'
        result = json.loads(redact(body))
        self.assertEqual(
            result, {"access_token": REDACTED, "expires_in": 600, "refresh_token": REDACTED, "id_token": REDACTED}
        )
        self.assertEqual(json.loads(redact(body.decode()))["access_token"], REDACTED)

    def test_redacts_form_encoded_strings(self):
        self.assertEqual(
            redact("username=bob&password=hunter2&client_id=api&grant_type=password&refresh_token=RT1"),
            f"username=bob&password={REDACTED}&client_id=api&grant_type=password&refresh_token={REDACTED}",
        )

    def test_redacts_repr_output(self):
        result = redact(repr({"username": "bob", "password": "hunter2"}))
        self.assertNotIn("hunter2", result)
        self.assertIn("'username': 'bob'", result)

    def test_redacts_bearer_tokens(self):
        self.assertEqual(redact("Authorization: Bearer eyJabc.def-ghi"), f"Authorization: {REDACTED}")
        self.assertEqual(redact("Bearer eyJabc.def-ghi"), f"Bearer {REDACTED}")

    def test_leaves_non_sensitive_values_untouched(self):
        self.assertEqual(redact("plain message"), "plain message")
        self.assertEqual(redact("not json {bad"), "not json {bad")
        self.assertEqual(redact(5), 5)
        self.assertIsNone(redact(None))

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
import os
import unittest
from unittest.mock import patch

from openc3.models.offline_access_model import OfflineAccessModel
from openc3.utilities.secret_cipher import SecretCipher, SecretCipherKeyError
from openc3.utilities.store import Store
from test.test_helper import capture_io, mock_redis


TOKEN = "eyJhbGciOiJIUzI1NiJ9.offline-refresh-token"


class TestOfflineAccessModel(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        env = {k: v for k, v in os.environ.items() if k != "OPENC3_SECRETS_KEY_FILE"}
        env["OPENC3_SECRETS_KEY"] = "ab" * 32
        patcher = patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_creates_new(self):
        model = OfflineAccessModel(name="ps", scope="DEFAULT")
        self.assertIsInstance(model, OfflineAccessModel)
        self.assertIsNone(model.as_json()["offline_access_token"])

    def test_self_get_all_names_empty(self):
        self.assertIsNone(OfflineAccessModel.get(name="ps", scope="DEFAULT"))
        self.assertEqual(OfflineAccessModel.all(scope="DEFAULT"), {})
        self.assertEqual(OfflineAccessModel.names(scope="DEFAULT"), [])

    def test_token_is_encrypted_at_rest(self):
        model = OfflineAccessModel(name="alice", offline_access_token=TOKEN, scope="DEFAULT")
        self.assertEqual(model.offline_access_token, TOKEN)
        self.assertTrue(SecretCipher.is_encrypted(model.as_json()["offline_access_token"]))
        self.assertNotIn(TOKEN, json.dumps(model.as_json()))

        model.create()
        stored = OfflineAccessModel.get(name="alice", scope="DEFAULT")
        self.assertTrue(SecretCipher.is_encrypted(stored["offline_access_token"]))
        raw = Store.hget(OfflineAccessModel.PRIMARY_KEY, "alice")
        self.assertNotIn(TOKEN.encode(), raw)

    def test_token_is_decrypted_on_read(self):
        OfflineAccessModel(name="alice", offline_access_token=TOKEN, scope="DEFAULT").create()
        self.assertEqual(OfflineAccessModel.get_model(name="alice", scope="DEFAULT").offline_access_token, TOKEN)

    def test_update_and_clear(self):
        model = OfflineAccessModel(name="alice", offline_access_token=TOKEN, scope="DEFAULT")
        model.create()
        model.offline_access_token = "rotated-token"
        model.update()
        self.assertNotIn(b"rotated-token", Store.hget(OfflineAccessModel.PRIMARY_KEY, "alice"))
        self.assertEqual(
            OfflineAccessModel.get_model(name="alice", scope="DEFAULT").offline_access_token, "rotated-token"
        )
        model.offline_access_token = None
        model.update()
        self.assertIsNone(OfflineAccessModel.get_model(name="alice", scope="DEFAULT").offline_access_token)

    def test_reads_legacy_plaintext_and_re_encrypts(self):
        Store.hset(
            OfflineAccessModel.PRIMARY_KEY,
            "legacy",
            json.dumps({"name": "legacy", "offline_access_token": TOKEN, "scope": "DEFAULT"}),
        )
        model = OfflineAccessModel.get_model(name="legacy", scope="DEFAULT")
        self.assertEqual(model.offline_access_token, TOKEN)
        model.update()
        self.assertNotIn(TOKEN.encode(), Store.hget(OfflineAccessModel.PRIMARY_KEY, "legacy"))

    def test_token_bound_to_user_name(self):
        OfflineAccessModel(name="alice", offline_access_token=TOKEN, scope="DEFAULT").create()
        stored = OfflineAccessModel.get(name="alice", scope="DEFAULT")
        stored["name"] = "mallory"
        Store.hset(OfflineAccessModel.PRIMARY_KEY, "mallory", json.dumps(stored))
        for stdout in capture_io():
            self.assertIsNone(OfflineAccessModel.get_model(name="mallory", scope="DEFAULT").offline_access_token)
            self.assertIn("Unable to decrypt offline access token for mallory", stdout.getvalue())
            self.assertNotIn(TOKEN, stdout.getvalue())

    def test_different_key_treated_as_absent(self):
        OfflineAccessModel(name="alice", offline_access_token=TOKEN, scope="DEFAULT").create()
        with patch.dict(os.environ, {"OPENC3_SECRETS_KEY": "cd" * 32}):
            for stdout in capture_io():
                self.assertIsNone(OfflineAccessModel.get_model(name="alice", scope="DEFAULT").offline_access_token)
                self.assertIn("Unable to decrypt offline access token for alice", stdout.getvalue())

    def test_refuses_to_store_without_key(self):
        env = {k: v for k, v in os.environ.items() if k not in ("OPENC3_SECRETS_KEY", "OPENC3_SECRETS_KEY_FILE")}
        with patch.dict(os.environ, env, clear=True):
            model = OfflineAccessModel(name="alice", offline_access_token=TOKEN, scope="DEFAULT")
            with self.assertRaisesRegex(SecretCipherKeyError, "OPENC3_SECRETS_KEY"):
                model.create()
        self.assertIsNone(Store.hget(OfflineAccessModel.PRIMARY_KEY, "alice"))

    def test_decrypts_a_token_encrypted_by_the_ruby_secret_cipher(self):
        ruby_envelope = os.environ.get("RUBY_ENCRYPTED_FIXTURE")
        if not ruby_envelope:
            self.skipTest("RUBY_ENCRYPTED_FIXTURE not set")
        Store.hset(
            OfflineAccessModel.PRIMARY_KEY,
            "alice",
            json.dumps({"name": "alice", "offline_access_token": json.loads(ruby_envelope), "scope": "DEFAULT"}),
        )
        self.assertEqual(OfflineAccessModel.get_model(name="alice", scope="DEFAULT").offline_access_token, TOKEN)

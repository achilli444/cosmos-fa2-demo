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

import base64
import json
import os
import unittest
from unittest.mock import patch

from openc3.models.secret_model import SecretModel
from openc3.utilities import secret_encryption
from openc3.utilities.redis_secrets import RedisSecrets
from openc3.utilities.store import Store
from test.test_helper import mock_redis


class TestSecretEncryption(unittest.TestCase):
    def setUp(self):
        patcher = patch.dict(os.environ, {"OPENC3_SECRET_ENCRYPTION_KEY": "ab" * 32})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_round_trip(self):
        sealed = secret_encryption.encrypt("hunter2", "DEFAULT__openc3__secrets:PASSWORD")
        self.assertTrue(sealed.startswith("enc:v1:"))
        self.assertNotIn("hunter2", sealed)
        self.assertEqual(secret_encryption.decrypt(sealed, "DEFAULT__openc3__secrets:PASSWORD"), "hunter2")

    def test_fresh_iv(self):
        self.assertNotEqual(secret_encryption.encrypt("same", "ctx"), secret_encryption.encrypt("same", "ctx"))

    def test_rejects_moved_or_tampered(self):
        sealed = secret_encryption.encrypt("hunter2", "DEFAULT__openc3__secrets:PASSWORD")
        with self.assertRaisesRegex(secret_encryption.SecretEncryptionError, "tampered"):
            secret_encryption.decrypt(sealed, "OTHER__openc3__secrets:PASSWORD")
        parts = sealed.split(":")
        parts[4] = base64.b64encode(bytes(b ^ 0xFF for b in base64.b64decode(parts[4]))).decode()
        with self.assertRaises(secret_encryption.SecretEncryptionError):
            secret_encryption.decrypt(":".join(parts), "DEFAULT__openc3__secrets:PASSWORD")

    def test_legacy_plaintext(self):
        self.assertEqual(secret_encryption.decrypt("plain", "ctx"), "plain")
        self.assertIsNone(secret_encryption.decrypt(None, "ctx"))

    def test_missing_or_bad_key(self):
        with patch.dict(os.environ, {"OPENC3_SECRET_ENCRYPTION_KEY": ""}):
            self.assertFalse(secret_encryption.configured())
            self.assertRaises(secret_encryption.SecretEncryptionKeyMissingError, secret_encryption.encrypt, "x", "ctx")
        with patch.dict(os.environ, {"OPENC3_SECRET_ENCRYPTION_KEY": "tooshort"}):
            self.assertRaisesRegex(
                secret_encryption.SecretEncryptionError, "64 hex", secret_encryption.encrypt, "x", "ctx"
            )

    def test_decrypts_ruby_envelope(self):
        # Produced by openc3/lib/openc3/utilities/secret_encryption.rb with key 'ab' * 32
        ruby = os.environ.get("RUBY_ENVELOPE")
        if not ruby:
            self.skipTest("RUBY_ENVELOPE not provided")
        self.assertEqual(secret_encryption.decrypt(ruby, "DEFAULT__openc3__secrets:PASSWORD"), "hunter2")


class TestRedisSecretsEncryption(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        self.secrets = RedisSecrets()

    def test_never_writes_plaintext(self):
        self.secrets.set("PASSWORD", "hunter2", scope="DEFAULT")
        raw = Store.hget("DEFAULT__openc3__secrets", "PASSWORD")
        self.assertNotIn(b"hunter2", raw)
        self.assertTrue(json.loads(raw)["value"].startswith("enc:v1:"))
        self.assertEqual(self.secrets.get("PASSWORD", scope="DEFAULT"), "hunter2")
        self.assertEqual(self.secrets.keys(scope="DEFAULT"), ["PASSWORD"])
        model = SecretModel.get_model(name="PASSWORD", scope="DEFAULT")
        self.assertFalse(model.legacy_plaintext())
        self.assertEqual(model.value, "hunter2")
        self.assertEqual(model.as_json()["value"], json.loads(raw)["value"])

    def test_reads_legacy_plaintext(self):
        Store.hset("DEFAULT__openc3__secrets", "LEGACY", json.dumps({"name": "LEGACY", "value": "oldvalue"}))
        self.assertEqual(self.secrets.get("LEGACY", scope="DEFAULT"), "oldvalue")

    def test_refuses_without_key(self):
        with patch.dict(os.environ, {"OPENC3_SECRET_ENCRYPTION_KEY": ""}):
            self.assertRaises(
                secret_encryption.SecretEncryptionKeyMissingError,
                self.secrets.set,
                "PASSWORD",
                "hunter2",
                scope="DEFAULT",
            )
        self.assertIsNone(Store.hget("DEFAULT__openc3__secrets", "PASSWORD"))

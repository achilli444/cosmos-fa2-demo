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
import os
import unittest
from unittest.mock import patch

from openc3.utilities.logger import Logger
from openc3.utilities.redis_secrets import RedisSecrets
from openc3.utilities.secret_cipher import SecretCipherDecryptError, SecretCipherKeyError
from openc3.utilities.store import Store
from test.test_helper import mock_redis


class TestRedisSecrets(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        patcher = patch.dict(os.environ, {"OPENC3_SECRETS_KEY": "ab" * 32})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.secrets = RedisSecrets()

    def raw(self, name, scope="DEFAULT"):
        return Store.hget(f"{scope}__openc3__secrets", name)

    def raw_value(self, name, scope="DEFAULT"):
        return json.loads(self.raw(name, scope))["value"]

    def test_stores_only_ciphertext_and_returns_plaintext(self):
        self.secrets.set("MQTT_PASSWORD", "hunter2", scope="DEFAULT")
        raw = self.raw_value("MQTT_PASSWORD")
        self.assertIsInstance(raw, dict)
        self.assertEqual(raw["alg"], "aes-256-gcm")
        self.assertNotIn(b"hunter2", self.raw("MQTT_PASSWORD"))
        self.assertEqual(self.secrets.get("MQTT_PASSWORD", scope="DEFAULT"), "hunter2")
        self.assertEqual(self.secrets.keys(scope="DEFAULT"), ["MQTT_PASSWORD"])

    def test_stringifies_values(self):
        self.secrets.set("PORT", 8883, scope="DEFAULT")
        self.assertEqual(self.secrets.get("PORT", scope="DEFAULT"), "8883")

    def test_missing_secret_is_none(self):
        self.assertIsNone(self.secrets.get("NOPE", scope="DEFAULT"))

    def test_delete(self):
        self.secrets.set("MQTT_PASSWORD", "hunter2", scope="DEFAULT")
        self.secrets.delete("MQTT_PASSWORD", scope="DEFAULT")
        self.assertIsNone(self.secrets.get("MQTT_PASSWORD", scope="DEFAULT"))
        self.assertEqual(self.secrets.keys(scope="DEFAULT"), [])

    def test_reads_legacy_plaintext_and_warns(self):
        Store.hset("DEFAULT__openc3__secrets", "OLD", json.dumps({"name": "OLD", "value": "legacy"}))
        with patch.object(Logger.instance(), "warn") as warn:
            self.assertEqual(self.secrets.get("OLD", scope="DEFAULT"), "legacy")
        warn.assert_called_once()
        self.assertIn("Secret 'OLD' is stored unencrypted", warn.call_args.args[0])

    def test_reencrypts_legacy_on_set(self):
        Store.hset("DEFAULT__openc3__secrets", "OLD", json.dumps({"name": "OLD", "value": "legacy"}))
        self.secrets.set("OLD", "legacy", scope="DEFAULT")
        self.assertIsInstance(self.raw_value("OLD"), dict)
        self.assertEqual(self.secrets.get("OLD", scope="DEFAULT"), "legacy")

    def test_refuses_to_store_without_key(self):
        del os.environ["OPENC3_SECRETS_KEY"]
        with self.assertRaises(SecretCipherKeyError):
            self.secrets.set("MQTT_PASSWORD", "hunter2", scope="DEFAULT")
        self.assertIsNone(self.raw("MQTT_PASSWORD"))

    def test_rejects_ciphertext_copied_to_other_name(self):
        self.secrets.set("A", "hunter2", scope="DEFAULT")
        Store.hset("DEFAULT__openc3__secrets", "B", json.dumps({"name": "B", "value": self.raw_value("A")}))
        with self.assertRaises(SecretCipherDecryptError):
            self.secrets.get("B", scope="DEFAULT")

    def test_scopes_are_separate(self):
        self.secrets.set("PW", "one", scope="DEFAULT")
        self.secrets.set("PW", "two", scope="OTHER")
        self.assertEqual(self.secrets.get("PW", scope="DEFAULT"), "one")
        self.assertEqual(self.secrets.get("PW", scope="OTHER"), "two")

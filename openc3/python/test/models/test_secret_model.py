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
import unittest.mock
from unittest.mock import patch

from openc3.models.secret_model import SecretModel
from openc3.utilities.logger import Logger
from openc3.utilities.store import Store
from test.test_helper import *


class TestSecretModel(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        patcher = patch.dict(os.environ, {"OPENC3_SECRETS_KEY": "cd" * 32})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_creates_new(self):
        model = SecretModel(name="secret", value="tacit", scope="DEFAULT")
        self.assertIsInstance(model, SecretModel)

    def test_self_get(self):
        name = SecretModel.get(name="secret", scope="DEFAULT")
        self.assertIsNone(name)  # eq('secret')

    def test_self_all(self):
        all_secrets = SecretModel.all(scope="DEFAULT")
        self.assertEqual(all_secrets, {})  # eq('secret')

    def test_self_names(self):
        names = SecretModel.names(scope="DEFAULT")
        self.assertEqual(names, [])  # eq('secret')

    def test_as_json(self):
        model = SecretModel(name="secreter", value="silent", scope="DEFAULT")
        self.assertEqual(model.as_json()["name"], ("secreter"))

    def test_as_json_encrypts_value(self):
        model = SecretModel(name="secreter", value="silent", scope="DEFAULT")
        value = model.as_json()["value"]
        self.assertIsInstance(value, dict)
        self.assertEqual(value["alg"], "aes-256-gcm")
        self.assertNotIn("silent", json.dumps(model.as_json()))

    def test_round_trip(self):
        SecretModel.set({"name": "secret", "value": "tacit"}, scope="DEFAULT")
        self.assertEqual(SecretModel.get(name="secret", scope="DEFAULT")["value"], "tacit")
        self.assertEqual(SecretModel.all(scope="DEFAULT")["secret"]["value"], "tacit")
        self.assertEqual(SecretModel.names(scope="DEFAULT"), ["secret"])
        model = SecretModel.get_model(name="secret", scope="DEFAULT")
        self.assertEqual(model.as_json()["value"]["alg"], "aes-256-gcm")
        raw = json.loads(Store.hget("DEFAULT__openc3__secrets", "secret"))
        self.assertIsInstance(raw["value"], dict)
        self.assertNotIn("tacit", json.dumps(raw))

    def test_accepts_stored_envelope_as_value(self):
        SecretModel.set({"name": "secret", "value": "tacit"}, scope="DEFAULT")
        raw = json.loads(Store.hget("DEFAULT__openc3__secrets", "secret"))
        model = SecretModel(name="secret", value=raw["value"], scope="DEFAULT")
        model.create(force=True)
        self.assertEqual(SecretModel.get(name="secret", scope="DEFAULT")["value"], "tacit")

    def test_reads_legacy_plaintext(self):
        Store.hset("DEFAULT__openc3__secrets", "old", json.dumps({"name": "old", "value": "legacy"}))
        with patch.object(Logger.instance(), "warn"):
            self.assertEqual(SecretModel.get(name="old", scope="DEFAULT")["value"], "legacy")
            self.assertEqual(SecretModel.all(scope="DEFAULT")["old"]["value"], "legacy")

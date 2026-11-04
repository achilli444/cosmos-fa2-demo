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

import importlib
import os
import unittest
from unittest.mock import patch

import openc3.environment
from openc3.utilities.questdb_client import QuestDBClient
from openc3.utilities.store_implementation import Store


TRANSPORT_VARS = ("OPENC3_PLAINTEXT_TRANSPORT", "OPENC3_TLS_CA_FILE", "OPENC3_API_SCHEMA", "OPENC3_SCRIPT_API_SCHEMA")


def _load_environment(**env):
    """Re-import openc3.environment with only the given transport variables set."""
    with patch.dict(os.environ):
        for name in TRANSPORT_VARS:
            os.environ.pop(name, None)
        os.environ.update(env)
        return importlib.reload(openc3.environment)


class TestTransportSecurityEnvironment(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        importlib.reload(openc3.environment)

    def test_defaults_every_client_to_tls(self):
        env = _load_environment()
        self.assertFalse(env.OPENC3_PLAINTEXT_TRANSPORT)
        self.assertIsNone(env.OPENC3_TLS_CA_FILE)
        self.assertEqual(env.OPENC3_DEFAULT_HTTP_SCHEMA, "https")
        self.assertEqual(env.OPENC3_API_SCHEMA, "https")
        self.assertEqual(env.OPENC3_SCRIPT_API_SCHEMA, "https")
        self.assertEqual(env.OPENC3_TSDB_DEFAULT_SSLMODE, "verify-full")

    def test_plaintext_transport_restores_the_historical_defaults(self):
        env = _load_environment(OPENC3_PLAINTEXT_TRANSPORT="1")
        self.assertTrue(env.OPENC3_PLAINTEXT_TRANSPORT)
        self.assertEqual(env.OPENC3_API_SCHEMA, "http")
        self.assertEqual(env.OPENC3_SCRIPT_API_SCHEMA, "http")
        self.assertEqual(env.OPENC3_TSDB_DEFAULT_SSLMODE, "prefer")

    def test_explicit_schema_wins_over_the_default(self):
        env = _load_environment(OPENC3_API_SCHEMA="http", OPENC3_SCRIPT_API_SCHEMA="http")
        self.assertEqual(env.OPENC3_API_SCHEMA, "http")
        self.assertEqual(env.OPENC3_SCRIPT_API_SCHEMA, "http")

    def test_ca_file(self):
        env = _load_environment(OPENC3_TLS_CA_FILE="")
        self.assertIsNone(env.OPENC3_TLS_CA_FILE)
        env = _load_environment(OPENC3_TLS_CA_FILE="/etc/openc3/ca.pem")
        self.assertEqual(env.OPENC3_TLS_CA_FILE, "/etc/openc3/ca.pem")


class TestStoreTlsOptions(unittest.TestCase):
    def test_peer_verified_tls_by_default(self):
        with (
            patch("openc3.utilities.store_implementation.OPENC3_PLAINTEXT_TRANSPORT", False),
            patch("openc3.utilities.store_implementation.OPENC3_TLS_CA_FILE", None),
        ):
            self.assertEqual(Store.tls_options(), {"ssl": True, "ssl_cert_reqs": "required"})

    def test_ca_bundle(self):
        with (
            patch("openc3.utilities.store_implementation.OPENC3_PLAINTEXT_TRANSPORT", False),
            patch("openc3.utilities.store_implementation.OPENC3_TLS_CA_FILE", "/etc/openc3/ca.pem"),
        ):
            self.assertEqual(
                Store.tls_options(), {"ssl": True, "ssl_cert_reqs": "required", "ssl_ca_certs": "/etc/openc3/ca.pem"}
            )

    def test_plaintext_opt_out(self):
        with patch("openc3.utilities.store_implementation.OPENC3_PLAINTEXT_TRANSPORT", True):
            self.assertEqual(Store.tls_options(), {})

    def test_build_redis_passes_tls_options(self):
        with (
            patch("valkey.Valkey") as valkey_new,
            patch("openc3.utilities.store_implementation.OPENC3_PLAINTEXT_TRANSPORT", False),
            patch("openc3.utilities.store_implementation.OPENC3_TLS_CA_FILE", None),
        ):
            store = Store.__new__(Store)
            store.redis_host = "openc3-redis"
            store.redis_port = 6379
            store.build_redis()
        _, kwargs = valkey_new.call_args
        self.assertTrue(kwargs["ssl"])
        self.assertEqual(kwargs["ssl_cert_reqs"], "required")


class TestQuestDBTlsParams(unittest.TestCase):
    def test_verify_full_by_default(self):
        with (
            patch("openc3.utilities.questdb_client.OPENC3_TSDB_DEFAULT_SSLMODE", "verify-full"),
            patch("openc3.utilities.questdb_client.OPENC3_TLS_CA_FILE", None),
            patch.dict(os.environ, {}, clear=False),
        ):
            os.environ.pop("OPENC3_TSDB_SSLMODE", None)
            self.assertEqual(QuestDBClient.tls_connection_params(), {"sslmode": "verify-full"})

    def test_sslmode_override_and_ca_bundle(self):
        with (
            patch("openc3.utilities.questdb_client.OPENC3_TSDB_DEFAULT_SSLMODE", "verify-full"),
            patch("openc3.utilities.questdb_client.OPENC3_TLS_CA_FILE", "/etc/openc3/ca.pem"),
            patch.dict(os.environ, {"OPENC3_TSDB_SSLMODE": "require"}),
        ):
            self.assertEqual(
                QuestDBClient.tls_connection_params(), {"sslmode": "require", "sslrootcert": "/etc/openc3/ca.pem"}
            )

    def test_query_connection_uses_tls_params(self):
        with (
            patch("openc3.utilities.questdb_client.psycopg.connect") as connect,
            patch("openc3.utilities.questdb_client.OPENC3_TSDB_DEFAULT_SSLMODE", "verify-full"),
            patch("openc3.utilities.questdb_client.OPENC3_TLS_CA_FILE", None),
            patch.dict(os.environ, {"OPENC3_TSDB_HOSTNAME": "openc3-tsdb"}),
        ):
            os.environ.pop("OPENC3_TSDB_SSLMODE", None)
            QuestDBClient._create_query_connection(0, connect_timeout=2)
        _, kwargs = connect.call_args
        self.assertEqual(kwargs["sslmode"], "verify-full")
        self.assertEqual(kwargs["connect_timeout"], 2)
        self.assertEqual(kwargs["host"], "openc3-tsdb")

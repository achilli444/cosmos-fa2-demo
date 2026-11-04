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

from questdb.ingress import Protocol, TlsCa

import openc3.script
from openc3.script.storage import _get_uri
from openc3.utilities import tls_config
from openc3.utilities.questdb_client import QuestDBClient
from openc3.utilities.store_implementation import Store


TLS_ENV_KEYS = [
    "OPENC3_REDIS_TLS",
    "OPENC3_REDIS_TLS_CA_FILE",
    "OPENC3_REDIS_TLS_CERT_FILE",
    "OPENC3_REDIS_TLS_KEY_FILE",
    "OPENC3_TSDB_TLS",
    "OPENC3_TSDB_TLS_CA_FILE",
    "OPENC3_BUCKET_TLS",
    "OPENC3_BUCKET_TLS_CA_FILE",
    "OPENC3_BUCKET_URL",
]


class TestTlsConfig(unittest.TestCase):
    def setUp(self):
        env = {k: v for k, v in os.environ.items() if k not in TLS_ENV_KEYS}
        patcher = patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    # Redis / Valkey

    def test_redis_defaults_to_plaintext(self):
        self.assertFalse(tls_config.redis_tls())
        self.assertEqual(tls_config.redis_kwargs(), {})

    def test_redis_tls_enables_ssl_with_verification(self):
        os.environ["OPENC3_REDIS_TLS"] = "1"
        self.assertEqual(
            tls_config.redis_kwargs(),
            {"ssl": True, "ssl_cert_reqs": "required", "ssl_check_hostname": True},
        )

    def test_redis_tls_ca_and_client_cert(self):
        os.environ["OPENC3_REDIS_TLS"] = "true"
        os.environ["OPENC3_REDIS_TLS_CA_FILE"] = "/certs/ca.pem"
        os.environ["OPENC3_REDIS_TLS_CERT_FILE"] = "/certs/client.pem"
        os.environ["OPENC3_REDIS_TLS_KEY_FILE"] = "/certs/client.key"
        kwargs = tls_config.redis_kwargs()
        self.assertEqual(kwargs["ssl_ca_certs"], "/certs/ca.pem")
        self.assertEqual(kwargs["ssl_certfile"], "/certs/client.pem")
        self.assertEqual(kwargs["ssl_keyfile"], "/certs/client.key")

    def test_redis_tls_cert_requires_key(self):
        os.environ["OPENC3_REDIS_TLS"] = "1"
        os.environ["OPENC3_REDIS_TLS_KEY_FILE"] = "/certs/client.key"
        with self.assertRaisesRegex(tls_config.TlsConfigError, "must be set together"):
            tls_config.redis_kwargs()

    @patch("openc3.utilities.store_implementation.valkey.Valkey")
    def test_store_build_redis_passes_tls_kwargs(self, mock_valkey):
        os.environ["OPENC3_REDIS_TLS"] = "1"
        os.environ["OPENC3_REDIS_TLS_CA_FILE"] = "/certs/ca.pem"
        store = Store.__new__(Store)
        store.redis_host = "openc3-redis"
        store.redis_port = 6379
        store.build_redis()
        kwargs = mock_valkey.call_args.kwargs
        self.assertEqual(kwargs["host"], "openc3-redis")
        self.assertEqual(kwargs["port"], 6379)
        self.assertTrue(kwargs["ssl"])
        self.assertEqual(kwargs["ssl_cert_reqs"], "required")
        self.assertTrue(kwargs["ssl_check_hostname"])
        self.assertEqual(kwargs["ssl_ca_certs"], "/certs/ca.pem")

    @patch("openc3.utilities.store_implementation.valkey.Valkey")
    def test_store_build_redis_plaintext_without_tls(self, mock_valkey):
        store = Store.__new__(Store)
        store.redis_host = "openc3-redis"
        store.redis_port = 6379
        store.build_redis()
        self.assertNotIn("ssl", mock_valkey.call_args.kwargs)

    # QuestDB

    def test_tsdb_defaults_to_plaintext(self):
        self.assertEqual(tls_config.tsdb_pg_kwargs(), {})
        self.assertEqual(tls_config.tsdb_ilp_protocol(), Protocol.Http)
        self.assertEqual(tls_config.tsdb_ilp_kwargs(), {})

    def test_tsdb_tls_verify_full_with_system_roots(self):
        os.environ["OPENC3_TSDB_TLS"] = "1"
        self.assertEqual(tls_config.tsdb_pg_kwargs(), {"sslmode": "verify-full", "sslrootcert": "system"})
        self.assertEqual(tls_config.tsdb_ilp_protocol(), Protocol.Https)
        self.assertEqual(tls_config.tsdb_ilp_kwargs(), {"tls_ca": TlsCa.WebpkiAndOsRoots})

    def test_tsdb_tls_with_ca_file(self):
        os.environ["OPENC3_TSDB_TLS"] = "1"
        os.environ["OPENC3_TSDB_TLS_CA_FILE"] = "/certs/tsdb-ca.pem"
        self.assertEqual(tls_config.tsdb_pg_kwargs(), {"sslmode": "verify-full", "sslrootcert": "/certs/tsdb-ca.pem"})
        self.assertEqual(tls_config.tsdb_ilp_kwargs(), {"tls_ca": TlsCa.PemFile, "tls_roots": "/certs/tsdb-ca.pem"})

    @patch("openc3.utilities.questdb_client.psycopg.connect")
    def test_query_connection_passes_sslmode(self, mock_connect):
        os.environ["OPENC3_TSDB_TLS"] = "1"
        os.environ["OPENC3_TSDB_HOSTNAME"] = "openc3-tsdb"
        os.environ["OPENC3_TSDB_QUERY_PORT"] = "8812"
        os.environ["OPENC3_TSDB_USERNAME"] = "quest"
        os.environ["OPENC3_TSDB_PASSWORD"] = "password"
        QuestDBClient._create_query_connection(autocommit=True)
        mock_connect.assert_called_once_with(
            host="openc3-tsdb",
            port="8812",
            user="quest",
            password="password",
            dbname="qdb",
            sslmode="verify-full",
            sslrootcert="system",
            autocommit=True,
        )

    @patch("openc3.utilities.questdb_client.Sender")
    def test_connect_ingest_uses_https(self, mock_sender):
        os.environ["OPENC3_TSDB_TLS"] = "1"
        os.environ["OPENC3_TSDB_TLS_CA_FILE"] = "/certs/tsdb-ca.pem"
        os.environ["OPENC3_TSDB_HOSTNAME"] = "openc3-tsdb"
        os.environ["OPENC3_TSDB_INGEST_PORT"] = "9000"
        os.environ["OPENC3_TSDB_QUERY_PORT"] = "8812"
        os.environ["OPENC3_TSDB_USERNAME"] = "quest"
        os.environ["OPENC3_TSDB_PASSWORD"] = "password"
        client = QuestDBClient.__new__(QuestDBClient)
        client.name = "TEST"
        client.db_shard = 0
        client.ingest = None
        client.connect_ingest()
        mock_sender.assert_called_once_with(
            Protocol.Https,
            "openc3-tsdb",
            9000,
            username="quest",
            password="password",
            tls_ca=TlsCa.PemFile,
            tls_roots="/certs/tsdb-ca.pem",
        )

    @patch("openc3.utilities.questdb_client.Sender")
    def test_connect_ingest_plaintext_without_tls(self, mock_sender):
        os.environ["OPENC3_TSDB_HOSTNAME"] = "openc3-tsdb"
        os.environ["OPENC3_TSDB_INGEST_PORT"] = "9000"
        os.environ["OPENC3_TSDB_USERNAME"] = "quest"
        os.environ["OPENC3_TSDB_PASSWORD"] = "password"
        client = QuestDBClient.__new__(QuestDBClient)
        client.name = "TEST"
        client.db_shard = 0
        client.ingest = None
        client.connect_ingest()
        mock_sender.assert_called_once_with(Protocol.Http, "openc3-tsdb", 9000, username="quest", password="password")

    # Buckets

    def test_bucket_defaults_to_plaintext_endpoint(self):
        self.assertEqual(tls_config.bucket_endpoint(), "http://openc3-buckets:9000")
        self.assertEqual(tls_config.bucket_endpoint(devel=True), "http://127.0.0.1:9000")
        self.assertIs(tls_config.bucket_verify(), True)

    def test_bucket_url_override(self):
        os.environ["OPENC3_BUCKET_URL"] = "http://buckets.example:9000"
        self.assertEqual(tls_config.bucket_endpoint(), "http://buckets.example:9000")

    def test_bucket_tls_defaults_to_https(self):
        os.environ["OPENC3_BUCKET_TLS"] = "1"
        self.assertEqual(tls_config.bucket_endpoint(), "https://openc3-buckets:9000")
        self.assertEqual(tls_config.bucket_endpoint(devel=True), "https://127.0.0.1:9000")

    def test_bucket_tls_accepts_https_url(self):
        os.environ["OPENC3_BUCKET_TLS"] = "1"
        os.environ["OPENC3_BUCKET_URL"] = "HTTPS://buckets.example:9000"
        self.assertEqual(tls_config.bucket_endpoint(), "HTTPS://buckets.example:9000")

    def test_bucket_tls_rejects_plaintext_url(self):
        os.environ["OPENC3_BUCKET_TLS"] = "1"
        os.environ["OPENC3_BUCKET_URL"] = "http://openc3-buckets:9000"
        with self.assertRaisesRegex(tls_config.TlsConfigError, "is not https"):
            tls_config.bucket_endpoint()

    def test_bucket_ca_file_used_for_verify(self):
        os.environ["OPENC3_BUCKET_TLS_CA_FILE"] = "/certs/bucket-ca.pem"
        self.assertEqual(tls_config.bucket_verify(), "/certs/bucket-ca.pem")

    def test_script_storage_uri_uses_https_endpoint(self):
        os.environ["OPENC3_BUCKET_TLS"] = "1"
        saved = openc3.script.OPENC3_IN_CLUSTER
        openc3.script.OPENC3_IN_CLUSTER = True
        try:
            self.assertEqual(_get_uri("/config/file?sig=1"), "https://openc3-buckets:9000/config/file?sig=1")
            os.environ["OPENC3_BUCKET_URL"] = "http://openc3-buckets:9000"
            with self.assertRaises(tls_config.TlsConfigError):
                _get_uri("/config/file")
        finally:
            openc3.script.OPENC3_IN_CLUSTER = saved

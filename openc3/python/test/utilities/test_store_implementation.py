# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

import unittest
from unittest.mock import patch

from valkey.backoff import EqualJitterBackoff
from valkey.exceptions import BusyLoadingError, ConnectionError, TimeoutError
from valkey.retry import Retry

from openc3.utilities.store_implementation import Store


class TestStoreImplementation(unittest.TestCase):
    def test_help(self):
        help(Store)

    def test_build_redis_configures_resilience(self):
        # A transient network blip (the same kind that makes targets reconnect)
        # must be retried inside the client with jittered backoff instead of
        # immediately surfacing a connection error to callers, which would
        # otherwise propagate up and kill the caller.
        with patch("valkey.Valkey") as valkey_new:
            # __new__ bypasses __init__ so we can exercise build_redis in
            # isolation without spinning up the connection pool / singleton.
            store = Store.__new__(Store)
            store.redis_host = "localhost"
            store.redis_port = 6379
            store.build_redis()

        self.assertEqual(valkey_new.call_count, 1)
        _, kwargs = valkey_new.call_args
        # Client retries with equal-jitter backoff on connection/timeout errors
        retry = kwargs["retry"]
        self.assertIsInstance(retry, Retry)
        self.assertEqual(retry._retries, 3)
        self.assertIsInstance(retry._backoff, EqualJitterBackoff)
        self.assertIn(BusyLoadingError, kwargs["retry_on_error"])
        self.assertIn(ConnectionError, kwargs["retry_on_error"])
        self.assertIn(TimeoutError, kwargs["retry_on_error"])
        # Per-retry backoff is bounded so a single retry can't hang forever;
        # the final (3rd) retry tops out at the 5s cap (jittered, so 2.5-5s).
        self.assertEqual(retry._backoff._cap, 5)
        self.assertLessEqual(retry._backoff.compute(3), 5)

    # Redis carries commands, telemetry, AUTH passwords and secret values, so
    # SC-8 / SC-8(1) hardened deployments need the link encrypted and the
    # server verified. TLS is opt-in so existing plaintext deployments are
    # unchanged, but once enabled verification can never be turned off.
    def _build_redis_kwargs(self):
        with patch("valkey.Valkey") as valkey_new:
            store = Store.__new__(Store)
            store.redis_host = "localhost"
            store.redis_port = 6379
            store.build_redis()
        _, kwargs = valkey_new.call_args
        return kwargs

    def test_build_redis_defaults_to_plaintext(self):
        with patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS", False):
            kwargs = self._build_redis_kwargs()
        self.assertNotIn("ssl", kwargs)
        self.assertNotIn("ssl_cert_reqs", kwargs)

    def test_build_redis_tls_verifies_server_against_system_cas(self):
        with (
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS", True),
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS_CA_FILE", None),
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS_CERT_FILE", None),
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS_KEY_FILE", None),
        ):
            kwargs = self._build_redis_kwargs()
        self.assertTrue(kwargs["ssl"])
        self.assertEqual(kwargs["ssl_cert_reqs"], "required")
        self.assertTrue(kwargs["ssl_check_hostname"])
        self.assertIsNone(kwargs["ssl_ca_certs"])  # valkey falls back to the system CA store
        self.assertNotIn("ssl_certfile", kwargs)

    def test_build_redis_tls_uses_ca_file_and_client_cert(self):
        with (
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS", True),
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS_CA_FILE", "/certs/ca.crt"),
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS_CERT_FILE", "/certs/client.crt"),
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS_KEY_FILE", "/certs/client.key"),
        ):
            kwargs = self._build_redis_kwargs()
        self.assertTrue(kwargs["ssl"])
        self.assertEqual(kwargs["ssl_cert_reqs"], "required")
        self.assertEqual(kwargs["ssl_ca_certs"], "/certs/ca.crt")
        self.assertEqual(kwargs["ssl_certfile"], "/certs/client.crt")
        self.assertEqual(kwargs["ssl_keyfile"], "/certs/client.key")

    def test_build_redis_tls_rejects_client_cert_without_key(self):
        with (
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS", True),
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS_CERT_FILE", "/certs/client.crt"),
            patch("openc3.utilities.store_implementation.OPENC3_REDIS_TLS_KEY_FILE", None),
            self.assertRaises(RuntimeError),
        ):
            self._build_redis_kwargs()

    def test_environment_parses_redis_tls_flag(self):
        import importlib
        import os

        import openc3.environment as env

        with patch.dict(os.environ, {"OPENC3_REDIS_TLS": "1", "OPENC3_REDIS_TLS_CA_FILE": "/certs/ca.crt"}):
            importlib.reload(env)
            self.assertTrue(env.OPENC3_REDIS_TLS)
            self.assertEqual(env.OPENC3_REDIS_TLS_CA_FILE, "/certs/ca.crt")
        with patch.dict(os.environ, {"OPENC3_REDIS_TLS": "0", "OPENC3_REDIS_TLS_CA_FILE": ""}):
            importlib.reload(env)
            self.assertFalse(env.OPENC3_REDIS_TLS)
            self.assertIsNone(env.OPENC3_REDIS_TLS_CA_FILE)
        importlib.reload(env)

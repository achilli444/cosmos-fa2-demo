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
import shutil
import stat
import tempfile
import unittest
from unittest.mock import Mock

from openc3.utilities.mqtt_tls import configure_client_tls, temporary_pem_files


class TestTemporaryPemFiles(unittest.TestCase):
    def setUp(self):
        # Point the stdlib tempfile module at a private directory so the test can
        # prove nothing is left behind anywhere, not just at the paths it knows about
        self.tmpdir = tempfile.mkdtemp()
        self.saved_tempdir = tempfile.tempdir
        tempfile.tempdir = self.tmpdir

    def tearDown(self):
        tempfile.tempdir = self.saved_tempdir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_writes_each_pem_to_a_private_file_and_removes_it_on_exit(self):
        with temporary_pem_files(cert="CERT PEM", key="KEY PEM", ca_file=None) as paths:
            self.assertEqual(sorted(paths.keys()), ["cert", "key"])
            with open(paths["key"]) as file:
                self.assertEqual(file.read(), "KEY PEM")
            with open(paths["cert"]) as file:
                self.assertEqual(file.read(), "CERT PEM")
            self.assertEqual(stat.S_IMODE(os.stat(paths["key"]).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(paths["cert"]).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(paths["key"])).st_mode), 0o700)
        self.assertFalse(os.path.exists(paths["key"]))
        self.assertFalse(os.path.exists(os.path.dirname(paths["key"])))
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_removes_the_files_when_the_body_raises(self):
        with self.assertRaises(RuntimeError), temporary_pem_files(key="KEY PEM") as paths:
            raise RuntimeError("tls_set failed")
        self.assertFalse(os.path.exists(paths["key"]))
        self.assertEqual(os.listdir(self.tmpdir), [])


class TestConfigureClientTls(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.saved_tempdir = tempfile.tempdir
        tempfile.tempdir = self.tmpdir
        self.client = Mock()
        self.seen = {}

        def capture(**kwargs):
            # Record what paho would have read while the files still exist
            for name, path in kwargs.items():
                if name == "keyfile_password":
                    self.seen[name] = path
                    continue
                with open(path) as file:
                    self.seen[name] = (file.read(), stat.S_IMODE(os.stat(path).st_mode))

        self.client.tls_set.side_effect = capture

    def tearDown(self):
        tempfile.tempdir = self.saved_tempdir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_does_nothing_without_tls_options(self):
        configure_client_tls(self.client)
        self.client.tls_set.assert_not_called()
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_ssl_only_uses_default_certs(self):
        configure_client_tls(self.client, ssl=True)
        self.client.tls_set.assert_called_once_with()
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_client_cert_material_exists_only_during_tls_set(self):
        configure_client_tls(self.client, cert="CERT PEM", key="KEY PEM", ca_file="CA PEM")
        self.client.tls_set.assert_called_once()
        self.assertEqual(self.seen["certfile"], ("CERT PEM", 0o600))
        self.assertEqual(self.seen["keyfile"], ("KEY PEM", 0o600))
        self.assertEqual(self.seen["ca_certs"], ("CA PEM", 0o600))
        self.assertNotIn("keyfile_password", self.client.tls_set.call_args.kwargs)
        for path in self.client.tls_set.call_args.kwargs.values():
            self.assertFalse(os.path.exists(path))
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_passes_keyfile_password_through(self):
        configure_client_tls(self.client, cert="CERT PEM", key="KEY PEM", ca_file="CA PEM", keyfile_password="hunter2")
        self.assertEqual(self.seen["keyfile_password"], "hunter2")
        self.assertEqual(self.seen["keyfile"], ("KEY PEM", 0o600))
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_ca_file_only(self):
        configure_client_tls(self.client, ca_file="CA PEM")
        self.client.tls_set.assert_called_once()
        self.assertEqual(list(self.client.tls_set.call_args.kwargs.keys()), ["ca_certs"])
        self.assertEqual(self.seen["ca_certs"], ("CA PEM", 0o600))
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_cert_without_ca_file_is_ignored_like_before(self):
        configure_client_tls(self.client, cert="CERT PEM", key="KEY PEM")
        self.client.tls_set.assert_not_called()
        self.assertEqual(os.listdir(self.tmpdir), [])

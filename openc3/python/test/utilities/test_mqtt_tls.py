# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

import os
import stat
import unittest
from unittest.mock import ANY, Mock

from openc3.utilities.mqtt_tls import configure_tls


class TestMqttTls(unittest.TestCase):
    def setUp(self):
        self.seen = {}
        self.client = Mock()

        def record(**kwargs):
            for name, path in kwargs.items():
                if name == "keyfile_password":
                    continue
                with open(path) as file:
                    self.seen[name] = (
                        file.read(),
                        stat.S_IMODE(os.stat(path).st_mode),
                        stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode),
                    )

        self.client.tls_set.side_effect = record

    def test_loads_cert_key_and_ca_from_private_files_then_removes_them(self):
        configure_tls(self.client, cert="cert_content", key="key_content", ca_file="ca_content")
        self.client.tls_set.assert_called_once_with(ca_certs=ANY, certfile=ANY, keyfile=ANY)
        self.assertEqual(self.seen["keyfile"], ("key_content", 0o600, 0o700))
        self.assertEqual(self.seen["certfile"], ("cert_content", 0o600, 0o700))
        self.assertEqual(self.seen["ca_certs"], ("ca_content", 0o600, 0o700))
        for path in self.client.tls_set.call_args.kwargs.values():
            self.assertFalse(os.path.exists(path), path)
            self.assertFalse(os.path.exists(os.path.dirname(path)), path)

    def test_passes_the_keyfile_password(self):
        configure_tls(self.client, cert="c", key="k", ca_file="ca", keyfile_password="secret")
        self.client.tls_set.assert_called_once_with(ca_certs=ANY, certfile=ANY, keyfile=ANY, keyfile_password="secret")
        self.assertEqual(self.seen["keyfile"][0], "k")

    def test_loads_only_the_ca(self):
        configure_tls(self.client, ca_file="ca_content")
        self.client.tls_set.assert_called_once_with(ca_certs=ANY)
        self.assertEqual(self.seen["ca_certs"][0], "ca_content")
        self.assertFalse(os.path.exists(self.client.tls_set.call_args.kwargs["ca_certs"]))

    def test_removes_the_files_when_tls_set_raises(self):
        self.client.tls_set.side_effect = ValueError("bad key")
        with self.assertRaises(ValueError):
            configure_tls(self.client, cert="c", key="k", ca_file="ca")
        for path in self.client.tls_set.call_args.kwargs.values():
            self.assertFalse(os.path.exists(path), path)

    def test_does_nothing_without_cert_material(self):
        configure_tls(self.client)
        configure_tls(self.client, cert="c", key="k")  # no CA, matches prior behavior
        self.client.tls_set.assert_not_called()

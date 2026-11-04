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

from openc3.interfaces.protocols.protocol import Protocol
from openc3.interfaces.stream_interface import StreamInterface
from openc3.utilities.link_encryption_policy import PlaintextLinkError
from test.test_helper import mock_redis, setup_system


class FakeAeadProtocol(Protocol):
    def authenticated_encryption(self):
        return True


class TestLinkEncryptionPolicy(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        setup_system()
        self.saved = os.environ.pop("OPENC3_REQUIRE_ENCRYPTED_LINKS", None)
        self.interface = StreamInterface()

    def tearDown(self):
        os.environ.pop("OPENC3_REQUIRE_ENCRYPTED_LINKS", None)
        if self.saved is not None:
            os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = self.saved

    @patch("openc3.utilities.link_encryption_policy.Logger")
    def test_accepts_encrypted_transports_silently(self, logger):
        self.assertTrue(self.interface.enforce_link_encryption_policy("tls", encrypted=True))
        logger.warn.assert_not_called()

    @patch("openc3.utilities.link_encryption_policy.Logger")
    def test_warns_on_plaintext_by_default(self, logger):
        self.assertFalse(self.interface.enforce_link_encryption_policy("host:1234"))
        self.assertIn("plaintext link host:1234", logger.warn.call_args[0][0])

    def test_refuses_plaintext_when_required(self):
        for value in ["true", "1", "YES", "on"]:
            os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = value
            with self.assertRaisesRegex(PlaintextLinkError, "refusing plaintext link host:1234"):
                self.interface.enforce_link_encryption_policy("host:1234")

    @patch("openc3.utilities.link_encryption_policy.Logger")
    def test_false_does_not_refuse(self, logger):
        os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = "false"
        self.assertFalse(self.interface.enforce_link_encryption_policy("host:1234"))
        logger.warn.assert_called_once()

    @patch("openc3.utilities.link_encryption_policy.Logger")
    def test_permits_and_logs_approved_bypass(self, logger):
        os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = "true"
        self.interface.set_option("ALLOW_PLAINTEXT", ["true"])
        self.assertFalse(self.interface.enforce_link_encryption_policy("host:1234"))
        self.assertIn("permitted by ALLOW_PLAINTEXT", logger.warn.call_args[0][0])

    def test_ignores_allow_plaintext_false(self):
        os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = "true"
        self.interface.set_option("ALLOW_PLAINTEXT", ["false"])
        with self.assertRaises(PlaintextLinkError):
            self.interface.enforce_link_encryption_policy("host:1234")

    @patch("openc3.utilities.link_encryption_policy.Logger")
    def test_aead_protocol_in_both_directions_is_encrypted(self, logger):
        os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = "true"
        self.interface.add_protocol(FakeAeadProtocol, [], "READ_WRITE")
        self.assertTrue(self.interface.enforce_link_encryption_policy("host:1234"))
        logger.warn.assert_not_called()

    def test_aead_protocol_in_one_direction_is_refused(self):
        os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = "true"
        self.interface.add_protocol(FakeAeadProtocol, [], "READ")
        with self.assertRaises(PlaintextLinkError):
            self.interface.enforce_link_encryption_policy("host:1234")

    def test_read_only_interface_with_read_aead_is_encrypted(self):
        os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = "true"
        self.interface.write_allowed = False
        self.interface.add_protocol(FakeAeadProtocol, [], "READ")
        self.assertTrue(self.interface.enforce_link_encryption_policy("host:1234"))

    def test_tcpip_client_interface_is_gated(self):
        os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = "true"
        from openc3.interfaces.tcpip_client_interface import TcpipClientInterface

        i = TcpipClientInterface("localhost", "8888", "8889", "5", "5", "burst")
        with self.assertRaises(PlaintextLinkError):
            i.connect()
        self.assertFalse(i.connected())

    @patch("openc3.streams.mqtt_stream.mqtt.Client")
    def test_mqtt_stream_interface_with_ssl_passes(self, mock_client):
        os.environ["OPENC3_REQUIRE_ENCRYPTED_LINKS"] = "true"
        from openc3.interfaces.mqtt_stream_interface import MqttStreamInterface

        mock_client.return_value.is_connected.return_value = True
        i = MqttStreamInterface("localhost", "8883", True, "write_topic", "read_topic")
        i.connect()
        self.assertTrue(i.connected())
        plain = MqttStreamInterface("localhost", "1883", False, "write_topic", "read_topic")
        with self.assertRaises(PlaintextLinkError):
            plain.connect()

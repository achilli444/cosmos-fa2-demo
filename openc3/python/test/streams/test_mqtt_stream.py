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

import unittest
from unittest.mock import patch

from openc3.streams.mqtt_stream import MqttStream, resolve_mqtt_port, resolve_mqtt_ssl
from test.test_helper import mock_redis, setup_system


class TestMqttStream(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        setup_system()

    def test_resolve_mqtt_ssl(self):
        self.assertTrue(resolve_mqtt_ssl(None))
        self.assertTrue(resolve_mqtt_ssl("None"))
        self.assertTrue(resolve_mqtt_ssl("True"))
        self.assertFalse(resolve_mqtt_ssl(False))
        self.assertFalse(resolve_mqtt_ssl("FALSE"))

    def test_resolve_mqtt_port(self):
        self.assertEqual(resolve_mqtt_port(None, True), 8883)
        self.assertEqual(resolve_mqtt_port("None", True), 8883)
        self.assertEqual(resolve_mqtt_port(None, False), 1883)
        self.assertEqual(resolve_mqtt_port("1883", True), 1883)
        self.assertEqual(resolve_mqtt_port(9000, False), 9000)

    def test_defaults_to_tls_on_8883(self):
        s = MqttStream("localhost")
        self.assertTrue(s.ssl)
        self.assertEqual(s.port, 8883)
        s = MqttStream("localhost", None, False)
        self.assertFalse(s.ssl)
        self.assertEqual(s.port, 1883)

    @patch("openc3.streams.mqtt_stream.mqtt.Client")
    def test_verifies_the_broker_with_tls_by_default(self, mock_client):
        instance = mock_client.return_value
        instance.is_connected.return_value = True
        s = MqttStream("localhost", None, None, "write_topic", "read_topic")
        s.connect()
        # Paho tls_set() with no args == CERT_REQUIRED + system cert store + hostname check
        instance.tls_set.assert_called_once_with()
        instance.connect.assert_called_with("localhost", 8883)
        s.disconnect()

    @patch("openc3.streams.mqtt_stream.mqtt.Client")
    @patch("openc3.streams.mqtt_stream.Logger")
    def test_warns_when_tls_is_disabled(self, mock_logger, mock_client):
        instance = mock_client.return_value
        instance.is_connected.return_value = True
        s = MqttStream("localhost", None, False, "write_topic", "read_topic")
        s.connect()
        instance.tls_set.assert_not_called()
        instance.connect.assert_called_with("localhost", 1883)
        mock_logger.warn.assert_called_once()
        self.assertIn("plaintext", mock_logger.warn.call_args[0][0])
        s.disconnect()

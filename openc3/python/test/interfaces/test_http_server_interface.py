# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

import http.client
import os
import socket
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from openc3.interfaces.http_server_interface import HttpServerInterface
from openc3.packets.packet import Packet
from openc3.utilities.logger import Logger
from test.test_helper import mock_redis, setup_system


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def self_signed_cert(directory):
    cert = os.path.join(directory, "server.crt")
    key = os.path.join(directory, "server.key")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
            "-keyout", key, "-out", cert,
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return cert, key


class TestHttpServerInterface(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        setup_system()

    def test_initializes_the_instance_variables(self):
        i = HttpServerInterface(8080)
        self.assertEqual(i.name, "HttpServerInterface")
        self.assertEqual(i.port, 8080)
        self.assertEqual(i.listen_address, "127.0.0.1")
        self.assertEqual(i.max_queue_size, HttpServerInterface.DEFAULT_MAX_QUEUE_SIZE)
        self.assertFalse(i.ssl())
        self.assertIsNone(i.auth_token)

    def test_sets_the_listen_address(self):
        i = HttpServerInterface(8080)
        i.set_option("LISTEN_ADDRESS", ["0.0.0.0"])
        self.assertEqual(i.listen_address, "0.0.0.0")

    def test_sets_the_max_queue_size(self):
        i = HttpServerInterface(8080)
        i.set_option("MAX_QUEUE_SIZE", ["5"])
        self.assertEqual(i.max_queue_size, 5)
        with self.assertRaisesRegex(RuntimeError, "MAX_QUEUE_SIZE"):
            i.set_option("MAX_QUEUE_SIZE", ["0"])

    def test_rejects_an_empty_auth_token(self):
        i = HttpServerInterface(8080)
        with self.assertRaisesRegex(RuntimeError, "AUTH_TOKEN"):
            i.set_option("AUTH_TOKEN", [""])

    def test_accepts_pem_contents_or_filename(self):
        i = HttpServerInterface(8080)
        with tempfile.TemporaryDirectory() as directory:
            cert, key = self_signed_cert(directory)
            with open(cert) as file:
                i.set_option("CERT", [file.read()])
            i.set_option("KEY", [key])
            self.assertTrue(i.ssl())
            self.assertEqual(i.key, key)
            with open(i.cert) as file:
                self.assertTrue(file.read().startswith("-----BEGIN CERTIFICATE-----"))
        with self.assertRaisesRegex(RuntimeError, "PEM file not found"):
            i.set_option("CERT", ["/nonexistent/server.crt"])

    def test_requires_both_cert_and_key(self):
        i = HttpServerInterface(free_port())
        with tempfile.TemporaryDirectory() as directory:
            cert, _key = self_signed_cert(directory)
            i.set_option("CERT", [cert])
            with self.assertRaisesRegex(RuntimeError, "both CERT and KEY"):
                i.connect()
            i = HttpServerInterface(free_port())
            i.set_option("CA_FILE", [cert])
            with self.assertRaisesRegex(RuntimeError, "CA_FILE option requires CERT and KEY"):
                i.connect()

    def test_default_port(self):
        i = HttpServerInterface()
        self.assertEqual(i.port, 80)

    def test_connection_string(self):
        i = HttpServerInterface(8080)
        self.assertEqual(i.connection_string(), "listening on 127.0.0.1:8080")

    def test_connection_string_with_custom_listen_address(self):
        i = HttpServerInterface(8080)
        i.set_option("LISTEN_ADDRESS", ["127.0.0.1"])
        self.assertEqual(i.connection_string(), "listening on 127.0.0.1:8080")

    def test_details(self):
        i = HttpServerInterface(8080)
        details = i.details()

        # Verify it returns a dictionary
        self.assertIsInstance(details, dict)

        # Check that it includes the expected keys specific to HttpServerInterface
        self.assertIn("listen_address", details)
        self.assertIn("port", details)
        self.assertIn("request_queue_length", details)

        # Verify the specific values are correct
        self.assertEqual(details["listen_address"], "127.0.0.1")
        self.assertEqual(details["port"], 8080)
        self.assertFalse(details["ssl"])
        self.assertFalse(details["client_cert_required"])
        self.assertFalse(details["auth_token_required"])
        self.assertEqual(details["max_queue_size"], HttpServerInterface.DEFAULT_MAX_QUEUE_SIZE)
        self.assertEqual(details["request_queue_length"], 0)  # No server started

    def test_details_with_custom_listen_address(self):
        i = HttpServerInterface(9090)
        i.set_option("LISTEN_ADDRESS", ["192.168.1.100"])
        details = i.details()

        # Verify it returns a dictionary
        self.assertIsInstance(details, dict)

        # Check values with custom settings
        self.assertEqual(details["listen_address"], "192.168.1.100")
        self.assertEqual(details["port"], 9090)
        self.assertEqual(details["request_queue_length"], 0)

    def test_details_default_port(self):
        i = HttpServerInterface()  # Default port 80
        details = i.details()

        # Verify it returns a dictionary
        self.assertIsInstance(details, dict)

        # Check default port
        self.assertEqual(details["port"], 80)
        self.assertEqual(details["listen_address"], "127.0.0.1")


class TestHttpServerInterfaceRequests(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        setup_system()
        self.port = free_port()
        self.interface = HttpServerInterface(self.port)
        self.interface.target_names = ["INST"]
        self.tempdir = tempfile.TemporaryDirectory()
        self.cert, self.key = self_signed_cert(self.tempdir.name)

        # Mount a single INST packet at /test so one request queues one item
        def read(packet, name, *_args, **_kwargs):
            if name == "HTTP_PATH" and packet.packet_name != "COLLECT":
                raise RuntimeError("no HTTP_PATH")
            return {"HTTP_PATH": "/test", "HTTP_STATUS": 200, "HTTP_PACKET": "REQUEST"}[name]

        patcher = patch.object(Packet, "read", read)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tempdir.cleanup)

    def tearDown(self):
        self.interface.disconnect()

    def post(self, body, headers=None, context=None):
        if context is not None:
            conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=context, timeout=5)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("POST", "/test", body=body, headers=headers or {})
            response = conn.getresponse()
            response.read()
            return response
        finally:
            conn.close()

    def insecure_context(self, cert=None, key=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if cert:
            context.load_cert_chain(cert, key)
        return context

    def test_queues_requests_as_telemetry(self):
        self.interface.connect()
        self.assertEqual(self.post(b'{"a":1}').status, 200)
        data, extra = self.interface.read_interface()
        self.assertEqual(data, b'{"a":1}')
        self.assertEqual(extra["HTTP_REQUEST_TARGET_NAME"], "INST")
        self.assertEqual(extra["HTTP_REQUEST_PACKET_NAME"], "REQUEST")

    def test_rejects_requests_without_the_auth_token(self):
        self.interface.set_option("AUTH_TOKEN", ["s3cret"])
        self.interface.connect()
        self.assertEqual(self.post(b"1").status, 401)
        self.assertEqual(self.post(b"1", {"Authorization": "Bearer wrong"}).status, 401)
        self.assertEqual(self.post(b"1", {"Authorization": "s3cret"}).status, 401)
        self.assertEqual(self.interface.server.request_queue.qsize(), 0)
        self.assertEqual(self.post(b"1", {"Authorization": "Bearer s3cret"}).status, 200)
        data, _extra = self.interface.read_interface()
        self.assertEqual(data, b"1")

    def test_rejects_requests_once_the_queue_is_full(self):
        self.interface.set_option("MAX_QUEUE_SIZE", ["2"])
        self.interface.connect()
        self.assertEqual(self.post(b"1").status, 200)
        self.assertEqual(self.post(b"2").status, 200)
        response = self.post(b"3")
        self.assertEqual(response.status, 503)
        self.assertEqual(response.getheader("Retry-After"), "1")
        self.assertEqual(self.interface.server.request_queue.qsize(), 2)

    def test_serves_https_when_cert_and_key_are_given(self):
        self.interface.set_option("CERT", [self.cert])
        self.interface.set_option("KEY", [self.key])
        self.interface.connect()
        self.assertTrue(self.interface.details()["ssl"])
        self.assertEqual(self.post(b'{"a":1}', context=self.insecure_context()).status, 200)
        data, _extra = self.interface.read_interface()
        self.assertEqual(data, b'{"a":1}')
        with self.assertRaises((OSError, http.client.HTTPException)):
            self.post(b'{"a":1}')

    def test_requires_a_client_certificate_when_ca_file_is_given(self):
        self.interface.set_option("CERT", [self.cert])
        self.interface.set_option("KEY", [self.key])
        self.interface.set_option("CA_FILE", [self.cert])
        self.interface.connect()
        self.assertTrue(self.interface.details()["client_cert_required"])
        with self.assertRaises((OSError, http.client.HTTPException)):
            self.post(b"1", context=self.insecure_context())
        response = self.post(b"1", context=self.insecure_context(self.cert, self.key))
        self.assertEqual(response.status, 200)

    def test_warns_when_exposed_without_tls_or_auth(self):
        self.interface.set_option("LISTEN_ADDRESS", ["0.0.0.0"])
        with patch.object(Logger.instance(), "warn") as warn:
            self.interface.connect()
        warn.assert_called_once()
        self.assertIn("unauthenticated plain HTTP from any address", warn.call_args[0][0])


if __name__ == "__main__":
    unittest.main()

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
import shutil
import socket
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from openc3.interfaces.http_server_interface import HttpServerInterface
from test.test_helper import mock_redis, setup_system


# Self-signed CA plus server / client certificates signed by it, via the openssl CLI
def make_cert(cn, issuer=None, ca=False):
    directory = tempfile.mkdtemp()
    key = os.path.join(directory, "key.pem")
    cert = os.path.join(directory, "cert.pem")
    subprocess.run(["openssl", "genrsa", "-out", key, "2048"], check=True, capture_output=True)
    if ca:
        subprocess.run(
            ["openssl", "req", "-x509", "-new", "-key", key, "-subj", f"/CN={cn}", "-days", "1", "-out", cert],
            check=True,
            capture_output=True,
        )
    else:
        csr = os.path.join(directory, "req.csr")
        ext = os.path.join(directory, "ext.cnf")
        with open(ext, "w") as file:
            file.write("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        subprocess.run(
            ["openssl", "req", "-new", "-key", key, "-subj", f"/CN={cn}", "-out", csr], check=True, capture_output=True
        )
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                csr,
                "-CA",
                issuer[0],
                "-CAkey",
                issuer[1],
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                ext,
                "-out",
                cert,
            ],
            check=True,
            capture_output=True,
        )
    return cert, key


def pem(path):
    with open(path) as file:
        return file.read()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestHttpServerInterface(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        setup_system()

    def test_initializes_the_instance_variables(self):
        i = HttpServerInterface(8080)
        self.assertEqual(i.name, "HttpServerInterface")
        self.assertEqual(i.port, 8080)
        self.assertEqual(i.listen_address, "127.0.0.1")

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


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI required to generate test certificates")
class TestHttpServerInterfaceRequests(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        setup_system()
        self.port = free_port()
        self.interface = HttpServerInterface(self.port)
        packet = Mock()
        packet.target_name = "SERVER"
        packet.buffer = b"OK"
        packet.extra = None
        packet.read = lambda name: {"HTTP_STATUS": 200, "HTTP_PACKET": "REQUEST"}[name]
        self.lookup = {"/test": [packet]}

    def tearDown(self):
        self.interface.disconnect()

    def start(self):
        with patch.object(HttpServerInterface, "build_path_lookup", lambda i: setattr(i, "lookup", self.lookup)):
            self.interface.connect()

    def request(self, token=None, context=None):
        if context:
            conn = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=2, context=context)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers = {"Cookie": "session=abc", "X-Custom": "kept"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        conn.request("GET", "/test?temp=1", headers=headers)
        response = conn.getresponse()
        response.read()
        conn.close()
        return response

    def test_default_listen_address_is_loopback(self):
        self.assertEqual(self.interface.listen_address, "127.0.0.1")

    def test_accepts_requests_and_redacts_credential_headers(self):
        self.start()
        response = self.request()
        self.assertEqual(response.status, 200)
        _data, extra = self.interface.read_interface()
        self.assertEqual(extra["HTTP_QUERIES"], {"temp": "1"})
        self.assertEqual(extra["HTTP_HEADERS"]["x-custom"], "kept")
        self.assertNotIn("cookie", extra["HTTP_HEADERS"])
        self.assertNotIn("authorization", extra["HTTP_HEADERS"])

    def test_rejects_requests_without_the_auth_token(self):
        self.interface.set_option("AUTH_TOKEN", ["secret"])
        self.start()
        self.assertTrue(self.interface.details()["auth_token_required"])

        response = self.request()
        self.assertEqual(response.status, 401)
        self.assertEqual(response.getheader("WWW-Authenticate"), "Bearer")
        response = self.request(token="wrong")
        self.assertEqual(response.status, 401)
        self.assertEqual(self.interface.server.request_queue.qsize(), 0)

        response = self.request(token="secret")
        self.assertEqual(response.status, 200)
        _data, extra = self.interface.read_interface()
        self.assertNotIn("authorization", extra["HTTP_HEADERS"])

    def test_warns_when_exposed_without_authentication(self):
        self.interface.set_option("LISTEN_ADDRESS", ["0.0.0.0"])
        with patch("openc3.interfaces.http_server_interface.Logger") as logger:
            self.start()
            logger.warn.assert_called_once()
            self.assertIn("without AUTH_TOKEN or SSL_CA_FILE", logger.warn.call_args[0][0])

    def test_requires_both_ssl_cert_and_ssl_key(self):
        self.interface.set_option("SSL_CERT", ["cert"])
        with self.assertRaisesRegex(RuntimeError, "SSL_CERT and SSL_KEY must both be set"):
            self.start()
        self.interface.server = None

    def test_serves_https_and_refuses_plaintext(self):
        ca = make_cert("Test CA", ca=True)
        cert, key = make_cert("localhost", issuer=ca)
        self.interface.set_option("SSL_CERT", [pem(cert)])  # PEM contents
        self.interface.set_option("SSL_KEY", [key])  # or a file path
        self.start()
        self.assertTrue(self.interface.details()["ssl"])
        self.assertEqual(self.interface.connection_string(), f"listening on 127.0.0.1:{self.port} (ssl)")

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        response = self.request(context=context)
        self.assertEqual(response.status, 200)

        with self.assertRaises((OSError, http.client.HTTPException)):
            self.request()

    def test_requires_a_client_certificate_signed_by_ssl_ca_file(self):
        ca = make_cert("Test CA", ca=True)
        cert, key = make_cert("localhost", issuer=ca)
        client_cert, client_key = make_cert("client", issuer=ca)
        other_ca = make_cert("Other CA", ca=True)
        bad_cert, bad_key = make_cert("client", issuer=other_ca)
        self.interface.set_option("SSL_CERT", [pem(cert)])
        self.interface.set_option("SSL_KEY", [pem(key)])
        self.interface.set_option("SSL_CA_FILE", [pem(ca[0])])
        self.start()
        self.assertTrue(self.interface.details()["client_cert_required"])

        def client_context(cert_obj=None, key_obj=None):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            if cert_obj:
                context.load_cert_chain(cert_obj, key_obj)
            return context

        with self.assertRaises(ssl.SSLError):
            self.request(context=client_context())
        with self.assertRaises(ssl.SSLError):
            self.request(context=client_context(bad_cert, bad_key))
        response = self.request(context=client_context(client_cert, client_key))
        self.assertEqual(response.status, 200)

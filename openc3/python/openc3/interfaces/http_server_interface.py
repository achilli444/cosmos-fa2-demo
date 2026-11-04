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

import contextlib
import hmac
import os
import queue
import ssl
import tempfile
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from openc3.accessors.http_accessor import HttpAccessor
from openc3.interfaces.interface import Interface
from openc3.packets.packet import Packet
from openc3.system.system import System
from openc3.utilities.logger import Logger


# Request headers that carry credentials and must never be copied into
# packet.extra (which is published and logged with the telemetry)
SENSITIVE_HEADERS = ("authorization", "proxy-authorization", "cookie")
LOOPBACK_ADDRESSES = ("127.0.0.1", "::1", "localhost")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa
        self.handle_request()

    def do_GET(self):  # noqa
        self.handle_request()

    def authorized(self):
        token = self.server.auth_token
        if not token:
            return True
        scheme, _, presented = self.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer":
            return False
        return hmac.compare_digest(presented.strip().encode(), token.encode())

    def handle_request(self):
        base = self.path.split("?")[0]
        if self.server.lookup.get(base):
            if not self.authorized():
                Logger.warn(
                    f"{self.server.interface_name}: rejected unauthenticated request for {base} from {self.client_address[0]}"
                )
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            packets = self.server.lookup[base]
            status = 200

            for packet in packets:
                # Build the Response
                with contextlib.suppress(Exception):
                    # No HTTP_STATUS - Leave at default
                    status = int(packet.read("HTTP_STATUS"))

                self.send_response(status)

                # http_accessor stores all the pseudo-derived HTTP configuration in extra
                if packet.extra:
                    headers = packet.extra.get("HTTP_HEADERS")
                    if headers:
                        for key, value in headers:
                            self.send_header(key, value)
                self.end_headers()

                self.wfile.write(packet.buffer)

                # Save the Request
                packet_name = None
                with contextlib.suppress(Exception):
                    # No packet name means don't save the request as telemetry
                    packet_name = packet.read("HTTP_PACKET")

                if packet_name:
                    data = b""
                    if self.headers.get("content-length") and self.rfile:
                        length = int(self.headers.get("content-length"))
                        data = self.rfile.read(length)
                    extra = {}
                    extra["HTTP_REQUEST_TARGET_NAME"] = packet.target_name
                    extra["HTTP_REQUEST_PACKET_NAME"] = packet_name

                    if self.headers:
                        extra["HTTP_HEADERS"] = {}
                        for key, value in self.headers.items():
                            key = key.lower()
                            if key in SENSITIVE_HEADERS:
                                continue
                            extra["HTTP_HEADERS"][key] = value

                    queries = {}
                    if "?" in self.path:
                        query_string = self.path.split("?", 1)[1]
                        for query in query_string.split("&"):
                            key, value = query.split("=", 1)
                            queries[key] = value

                    if len(queries) > 0:
                        extra["HTTP_QUERIES"] = {}
                        for key, value in queries.items():
                            extra["HTTP_QUERIES"][key] = value

                    self.server.request_queue.put((data, extra))


class HttpServerInterface(Interface):
    # @param port [Integer] HTTP port
    def __init__(self, port=80):
        super().__init__()
        self.listen_address = "127.0.0.1"  # Default to loopback, LISTEN_ADDRESS 0.0.0.0 to expose
        self.port = int(port)
        self.server = None
        self.auth_token = None
        self.ssl_cert = None
        self.ssl_key = None
        self.ssl_ca_file = None

    def build_path_lookup(self):
        self.lookup = {}
        for target_name in self.target_names:
            for packet_name, packet in System.commands.packets(target_name).items():
                packet.restore_defaults()
                path = None
                try:
                    path = packet.read("HTTP_PATH")
                except Exception:
                    # No HTTP_PATH is an error
                    Logger.error(
                        f"HttpServerInterface Packet {target_name} {packet_name} unable to read HTTP_PATH\n{traceback.format_exc()}"
                    )
                if path:
                    self.lookup[path] = self.lookup.get(path) or []
                    self.lookup[path].append(packet)

    # Supported Options
    # LISTEN_ADDRESS - Ip address of the interface to accept connections on
    # AUTH_TOKEN - Shared secret clients must present as "Authorization: Bearer <token>"
    # SSL_CERT - PEM server certificate (contents or path), enables HTTPS with SSL_KEY
    # SSL_KEY - PEM server private key (contents or path)
    # SSL_CA_FILE - PEM CA bundle (contents or path), requires and verifies client certificates
    # (see Interface#set_option)
    def set_option(self, option_name, option_values):
        super().set_option(option_name, option_values)
        match option_name.upper():
            case "LISTEN_ADDRESS":
                self.listen_address = option_values[0]
            case "AUTH_TOKEN":
                self.auth_token = str(option_values[0]) or None
            case "SSL_CERT":
                self.ssl_cert = self._pem_file("cert", option_values[0])
            case "SSL_KEY":
                self.ssl_key = self._pem_file("key", option_values[0])
            case "SSL_CA_FILE":
                self.ssl_ca_file = self._pem_file("ca_file", option_values[0])

    # Accepts either PEM contents (e.g. from SECRET ... option) or a path to a PEM file
    # and returns a path the ssl module can load
    def _pem_file(self, name, value):
        value = str(value)
        if "\n" not in value and os.path.isfile(value):
            return value
        with tempfile.NamedTemporaryFile(mode="w+", prefix=name, delete=False) as file:
            file.write(value)
        return file.name

    def is_ssl(self):
        return bool(self.ssl_cert or self.ssl_key or self.ssl_ca_file)

    def connection_string(self):
        string = f"listening on {self.listen_address}:{self.port}"
        if self.is_ssl():
            string += " (ssl)"
        return string

    def _ssl_context(self):
        if not (self.ssl_cert and self.ssl_key):
            raise RuntimeError(f"{self.name}: SSL_CERT and SSL_KEY must both be set to enable HTTPS")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
        if self.ssl_ca_file:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self.ssl_ca_file)
        return context

    # Connects the interface to its target(s)
    def connect(self):
        # Can't build the lookup until after init because the target_names are not set
        self.build_path_lookup()
        self.server = ThreadingHTTPServer((self.listen_address, self.port), Handler)
        if self.is_ssl():
            self.server.socket = self._ssl_context().wrap_socket(self.server.socket, server_side=True)
        self.server.request_queue = queue.Queue()
        self.server.lookup = self.lookup
        self.server.auth_token = self.auth_token
        self.server.interface_name = self.name
        if self.listen_address not in LOOPBACK_ADDRESSES and not self.auth_token and not self.ssl_ca_file:
            Logger.warn(
                f"{self.name}: listening on {self.listen_address}:{self.port} without AUTH_TOKEN or SSL_CA_FILE, any host that can reach the port can inject telemetry"
            )
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.start()
        super().connect()

    def connected(self):
        return bool(self.server)

    # Disconnects the interface from its target(s)
    def disconnect(self):
        if self.server:
            self.server.shutdown()
            self.server_thread.join()
        self.server = None
        super().disconnect()

    def convert_packet_to_data(self, packet):
        raise RuntimeError("Commands cannot be sent to HttpServerInterface")

    def write_interface(self, data, extra=None):
        raise RuntimeError("Commands cannot be sent to HttpServerInterface")

    def read_interface(self):
        data, extra = self.server.request_queue.get(block=True)
        if data is None:
            return data, extra
        self.read_interface_base(data, extra)
        return data, extra

    # Called to convert the read data into a OpenC3 Packet object
    #
    # @param data [String] Raw packet data
    # @return [Packet] OpenC3 Packet with buffer filled with data
    def convert_data_to_packet(self, data, extra=None):
        packet = Packet(None, None, "BIG_ENDIAN", None, data)
        packet.accessor = HttpAccessor(packet)
        if extra:
            # Identify the response
            request_target_name = extra["HTTP_REQUEST_TARGET_NAME"]
            request_packet_name = extra["HTTP_REQUEST_PACKET_NAME"]
            if request_target_name and request_packet_name:
                packet.target_name = str(request_target_name).upper()
                packet.packet_name = str(request_packet_name).upper()
            extra.pop("HTTP_REQUEST_TARGET_NAME", None)
            extra.pop("HTTP_REQUEST_PACKET_NAME", None)
            packet.extra = extra

        return packet

    def details(self):
        result = super().details()
        result["listen_address"] = self.listen_address
        result["port"] = self.port
        result["ssl"] = self.is_ssl()
        result["client_cert_required"] = bool(self.ssl_ca_file)
        result["auth_token_required"] = bool(self.auth_token)
        if self.server is not None:
            result["request_queue_length"] = self.server.request_queue.qsize()
        else:
            result["request_queue_length"] = 0
        return result

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


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa
        self.handle_request()

    def do_GET(self):  # noqa
        self.handle_request()

    def authorized(self):
        token = self.server.auth_token
        if token is None:
            return True
        header = self.headers.get("Authorization") or ""
        if not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].encode(), token.encode())

    def handle_request(self):
        base = self.path.split("?")[0]
        if self.server.lookup.get(base):
            if not self.authorized():
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                self.end_headers()
                return

            packets = self.server.lookup[base]
            status = 200

            # Read the body once up front so it can be queued before the response is committed
            data = b""
            if self.headers.get("content-length") and self.rfile:
                length = int(self.headers.get("content-length"))
                data = self.rfile.read(length)

            for packet in packets:
                # Build the Response
                with contextlib.suppress(Exception):
                    # No HTTP_STATUS - Leave at default
                    status = int(packet.read("HTTP_STATUS"))

                # Save the Request
                packet_name = None
                with contextlib.suppress(Exception):
                    # No packet name means don't save the request as telemetry
                    packet_name = packet.read("HTTP_PACKET")

                if packet_name:
                    extra = {}
                    extra["HTTP_REQUEST_TARGET_NAME"] = packet.target_name
                    extra["HTTP_REQUEST_PACKET_NAME"] = packet_name

                    if self.headers:
                        extra["HTTP_HEADERS"] = {}
                        for key, value in self.headers.items():
                            extra["HTTP_HEADERS"][key.lower()] = value

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

                    try:
                        self.server.request_queue.put_nowait((data, extra))
                    except queue.Full:
                        # Queue is full - shed load rather than grow memory without bound
                        Logger.warn(
                            f"{self.server.interface_name}: request queue full ({self.server.request_queue.maxsize}), "
                            f"rejecting {self.command} {self.path}"
                        )
                        self.send_response(503)
                        self.send_header("Retry-After", "1")
                        self.end_headers()
                        return

                self.send_response(status)

                # http_accessor stores all the pseudo-derived HTTP configuration in extra
                if packet.extra:
                    headers = packet.extra.get("HTTP_HEADERS")
                    if headers:
                        for key, value in headers:
                            self.send_header(key, value)
                self.end_headers()

                self.wfile.write(packet.buffer)


class HttpServerInterface(Interface):
    # Only accept connections from the local host unless LISTEN_ADDRESS is explicitly widened
    DEFAULT_LISTEN_ADDRESS = "127.0.0.1"
    # Maximum number of requests buffered before read_interface drains them
    DEFAULT_MAX_QUEUE_SIZE = 1000

    # @param port [Integer] HTTP port
    def __init__(self, port=80):
        super().__init__()
        self.listen_address = self.DEFAULT_LISTEN_ADDRESS
        self.port = int(port)
        self.server = None
        self.server_thread = None
        self.max_queue_size = self.DEFAULT_MAX_QUEUE_SIZE
        self.cert = None
        self.key = None
        self.ca_file = None
        self.auth_token = None

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
    # LISTEN_ADDRESS - Ip address of the interface to accept connections on (default 127.0.0.1)
    # MAX_QUEUE_SIZE - Maximum number of buffered requests before new requests are rejected with 503
    # CERT - PEM encoded server certificate (contents or filename). Enables HTTPS when given with KEY.
    # KEY - PEM encoded server private key (contents or filename)
    # CA_FILE - PEM encoded CA bundle (contents or filename). Requires and verifies client certificates.
    # AUTH_TOKEN - Shared secret clients must send as 'Authorization: Bearer <token>'
    # (see Interface#set_option)
    def set_option(self, option_name, option_values):
        super().set_option(option_name, option_values)
        match option_name.upper():
            case "LISTEN_ADDRESS":
                self.listen_address = option_values[0]
            case "MAX_QUEUE_SIZE":
                self.max_queue_size = int(option_values[0])
                if self.max_queue_size <= 0:
                    raise RuntimeError("MAX_QUEUE_SIZE must be greater than 0")
            case "CERT":
                self.cert = self._pem_option_path(option_values[0], "cert")
            case "KEY":
                self.key = self._pem_option_path(option_values[0], "key")
            case "CA_FILE":
                self.ca_file = self._pem_option_path(option_values[0], "ca_file")
            case "AUTH_TOKEN":
                self.auth_token = str(option_values[0])
                if not self.auth_token:
                    raise RuntimeError("AUTH_TOKEN must not be empty")

    def ssl(self):
        return bool(self.cert and self.key)

    def connection_string(self):
        return f"listening on {self.listen_address}:{self.port}"

    # Connects the interface to its target(s)
    def connect(self):
        # Can't build the lookup until after init because the target_names are not set
        self.build_path_lookup()
        context = self._ssl_context()
        if self.listen_address == "0.0.0.0" and context is None and self.auth_token is None:
            Logger.warn(
                f"{self.name}: accepting unauthenticated plain HTTP from any address on port {self.port}. "
                "Set CERT/KEY, AUTH_TOKEN or LISTEN_ADDRESS to restrict access."
            )
        self.server = ThreadingHTTPServer((self.listen_address, self.port), Handler)
        if context is not None:
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.server.request_queue = queue.Queue(maxsize=self.max_queue_size)
        self.server.lookup = self.lookup
        self.server.auth_token = self.auth_token
        self.server.interface_name = self.name
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
            self.server.server_close()
        self.server = None
        self.server_thread = None
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
        result["ssl"] = self.ssl()
        result["client_cert_required"] = self.ca_file is not None
        result["auth_token_required"] = self.auth_token is not None
        result["max_queue_size"] = self.max_queue_size
        if self.server is not None:
            result["request_queue_length"] = self.server.request_queue.qsize()
        else:
            result["request_queue_length"] = 0
        return result

    # Option values may be the PEM text itself (e.g. injected from a SECRET) or a filename
    def _pem_option_path(self, value, prefix):
        value = str(value)
        if value.lstrip().startswith("-----BEGIN"):
            with tempfile.NamedTemporaryFile(mode="w+", prefix=prefix, delete=False) as file:
                file.write(value)
            return file.name
        if not os.path.isfile(value):
            raise RuntimeError(f"PEM file not found: {value}")
        return value

    def _ssl_context(self):
        if self.ssl():
            # Only TLS 1.2+ is negotiated
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile=self.cert, keyfile=self.key)
            if self.ca_file:
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations(cafile=self.ca_file)
            return context
        if self.cert or self.key:
            raise RuntimeError("HttpServerInterface requires both CERT and KEY options to enable HTTPS")
        if self.ca_file:
            raise RuntimeError("HttpServerInterface CA_FILE option requires CERT and KEY")
        return None

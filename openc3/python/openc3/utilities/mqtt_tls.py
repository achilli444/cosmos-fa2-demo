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
import tempfile
from contextlib import contextmanager


# paho's Client.tls_set() only accepts file paths and loads them into its
# ssl.SSLContext immediately, so PEM material handed to COSMOS as option
# strings only has to exist on disk for the duration of that call.
@contextmanager
def temporary_pem_files(**pem_contents):
    """Write each non-None PEM string to its own 0600 file inside a private
    0700 directory, yield {name: path}, and remove the directory on exit."""
    directory = tempfile.mkdtemp(prefix="openc3-mqtt-tls-")
    try:
        paths = {}
        for name, contents in pem_contents.items():
            if contents is None:
                continue
            path = os.path.join(directory, f"{name}.pem")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as file:
                file.write(contents)
            paths[name] = path
        yield paths
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def configure_client_tls(client, ssl=False, cert=None, key=None, ca_file=None, keyfile_password=None):
    """Apply the COSMOS MQTT SSL / client certificate options to a paho client.

    cert, key and ca_file are the PEM contents (strings), not paths. They are
    written to temporary files only while paho reads them and are deleted
    before this function returns."""
    if ssl:
        client.tls_set()
    # You still need the ca_file if you're using your own cert and key
    if cert and key and ca_file:
        with temporary_pem_files(ca_file=ca_file, cert=cert, key=key) as paths:
            if keyfile_password:
                client.tls_set(
                    ca_certs=paths["ca_file"],
                    certfile=paths["cert"],
                    keyfile=paths["key"],
                    keyfile_password=keyfile_password,
                )
            else:
                client.tls_set(
                    ca_certs=paths["ca_file"],
                    certfile=paths["cert"],
                    keyfile=paths["key"],
                )
    elif ca_file:
        with temporary_pem_files(ca_file=ca_file) as paths:
            client.tls_set(ca_certs=paths["ca_file"])

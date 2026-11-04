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
import tempfile
from contextlib import contextmanager


def configure_tls(client, cert=None, key=None, ca_file=None, keyfile_password=None):
    """Load client certificate authentication into a paho MQTT client.

    paho's tls_set (and ssl.SSLContext.load_cert_chain underneath it) only
    accepts file paths, so the PEM text is written to a private 0700 directory
    as 0600 files just long enough for the SSL context to load it. The
    directory and files are removed before this function returns.
    """
    # You still need the ca_file if you're using your own cert and key
    if cert and key and ca_file:
        with _pem_files(ca_file=ca_file, cert=cert, key=key) as paths:
            kwargs = {"ca_certs": paths["ca_file"], "certfile": paths["cert"], "keyfile": paths["key"]}
            if keyfile_password:
                kwargs["keyfile_password"] = keyfile_password
            client.tls_set(**kwargs)
    elif ca_file:
        with _pem_files(ca_file=ca_file) as paths:
            client.tls_set(ca_certs=paths["ca_file"])


@contextmanager
def _pem_files(**pems):
    # mkdtemp creates the directory 0700; the files are created 0600 and
    # everything is deleted when the block exits, even on error
    with tempfile.TemporaryDirectory(prefix="openc3-mqtt-tls-") as tmpdir:
        paths = {}
        for name, pem in pems.items():
            path = os.path.join(tmpdir, name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as file:
                file.write(pem)
            paths[name] = path
        yield paths

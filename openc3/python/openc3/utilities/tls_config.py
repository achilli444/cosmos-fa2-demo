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

"""Shared TLS settings for the internal service clients (Redis/Valkey, QuestDB,
S3-compatible buckets). The same environment variables drive the Ruby clients in
openc3/lib/openc3/utilities/tls_config.rb.

    OPENC3_REDIS_TLS=1             connect to Redis/Valkey with TLS and verify the server certificate
    OPENC3_REDIS_TLS_CA_FILE       PEM CA bundle used to verify the Redis server (default: system store)
    OPENC3_REDIS_TLS_CERT_FILE     PEM client certificate for mutual TLS (optional)
    OPENC3_REDIS_TLS_KEY_FILE      PEM client key for mutual TLS (optional)
    OPENC3_TSDB_TLS=1              use sslmode=verify-full for QuestDB PG connections and HTTPS for ILP ingest
    OPENC3_TSDB_TLS_CA_FILE        PEM CA bundle used to verify QuestDB (default: system store)
    OPENC3_BUCKET_TLS=1            require an https:// bucket endpoint (plaintext http:// endpoints are rejected)
    OPENC3_BUCKET_TLS_CA_FILE      PEM CA bundle used to verify the bucket endpoint (default: system store)

Certificate verification is always on when TLS is enabled; there is deliberately no
knob to turn it off. Supply the issuing CA via the *_CA_FILE variables instead.

Values are read from os.environ at call time (not import time) so a process can be
configured before the first connection is built.
"""

import os
from urllib.parse import urlparse

from openc3.environment import get_env_bool


DEFAULT_BUCKET_HOST = "openc3-buckets:9000"
DEFAULT_DEVEL_BUCKET_HOST = "127.0.0.1:9000"


class TlsConfigError(RuntimeError):
    pass


def _env_file(key: str) -> str | None:
    value = os.environ.get(key, "")
    return value if value else None


# Redis / Valkey


def redis_tls() -> bool:
    return get_env_bool("OPENC3_REDIS_TLS")


def redis_kwargs() -> dict:
    """Keyword arguments merged into valkey.Valkey(). Empty when TLS is disabled."""
    if not redis_tls():
        return {}
    kwargs = {"ssl": True, "ssl_cert_reqs": "required", "ssl_check_hostname": True}
    ca_file = _env_file("OPENC3_REDIS_TLS_CA_FILE")
    if ca_file:
        kwargs["ssl_ca_certs"] = ca_file
    cert_file = _env_file("OPENC3_REDIS_TLS_CERT_FILE")
    key_file = _env_file("OPENC3_REDIS_TLS_KEY_FILE")
    if (cert_file is None) != (key_file is None):
        raise TlsConfigError("OPENC3_REDIS_TLS_CERT_FILE and OPENC3_REDIS_TLS_KEY_FILE must be set together")
    if cert_file:
        kwargs["ssl_certfile"] = cert_file
        kwargs["ssl_keyfile"] = key_file
    return kwargs


# QuestDB


def tsdb_tls() -> bool:
    return get_env_bool("OPENC3_TSDB_TLS")


def tsdb_pg_kwargs() -> dict:
    """Keyword arguments merged into psycopg.connect(). Empty when TLS is disabled.

    sslmode=verify-full checks both the certificate chain and the hostname. Without an
    explicit CA file, libpq 16+ accepts sslrootcert=system to use the OS trust store.
    """
    if not tsdb_tls():
        return {}
    return {"sslmode": "verify-full", "sslrootcert": _env_file("OPENC3_TSDB_TLS_CA_FILE") or "system"}


def tsdb_ilp_protocol():
    """questdb.ingress.Protocol for the ILP sender: Https when TLS is enabled, otherwise Http."""
    from questdb.ingress import Protocol

    return Protocol.Https if tsdb_tls() else Protocol.Http


def tsdb_ilp_kwargs() -> dict:
    """Extra keyword arguments for questdb.ingress.Sender(). Empty when TLS is disabled."""
    if not tsdb_tls():
        return {}
    from questdb.ingress import TlsCa

    ca_file = _env_file("OPENC3_TSDB_TLS_CA_FILE")
    if ca_file:
        return {"tls_ca": TlsCa.PemFile, "tls_roots": ca_file}
    return {"tls_ca": TlsCa.WebpkiAndOsRoots}


# Buckets


def bucket_tls() -> bool:
    return get_env_bool("OPENC3_BUCKET_TLS")


def bucket_ca_file() -> str | None:
    return _env_file("OPENC3_BUCKET_TLS_CA_FILE")


def bucket_verify():
    """Value for boto3 / requests ``verify``: the CA bundle path when configured, else True."""
    return bucket_ca_file() or True


def bucket_endpoint(devel: bool = False) -> str:
    """Resolve the S3-compatible bucket endpoint for OPENC3_CLOUD=local.

    Uses OPENC3_BUCKET_URL when set, otherwise the in-cluster (or devel) default.
    When OPENC3_BUCKET_TLS is enabled the default becomes https:// and a plaintext
    http:// endpoint is rejected so a misconfiguration fails closed instead of
    silently sending credentials and mission data in the clear.
    """
    url = os.environ.get("OPENC3_BUCKET_URL", "")
    if not url:
        scheme = "https" if bucket_tls() else "http"
        url = f"{scheme}://{DEFAULT_DEVEL_BUCKET_HOST if devel else DEFAULT_BUCKET_HOST}"
    if bucket_tls() and urlparse(url).scheme.lower() != "https":
        raise TlsConfigError(f"OPENC3_BUCKET_TLS is enabled but OPENC3_BUCKET_URL '{url}' is not https://")
    return url

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

"""Encrypts secret values before they are written to Redis.

Mirrors openc3/lib/openc3/utilities/secret_encryption.rb byte for byte so
Ruby and Python services can read each other's secrets.

Algorithm: AES-256-GCM via the cryptography package (OpenSSL backend). The
key comes from the OPENC3_SECRET_ENCRYPTION_KEY environment variable as 64
hex characters (32 bytes), e.g. ``openssl rand -hex 32``.

Stored format: ``enc:v1:<base64 iv>:<base64 tag>:<base64 ciphertext>``.
The Redis primary key and field name are bound in as additional
authenticated data. Values without the ``enc:v1:`` prefix are legacy
plaintext and are returned unchanged on read.
"""

import base64
import os
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_ENV = "OPENC3_SECRET_ENCRYPTION_KEY"
PREFIX = "enc:v1:"
KEY_BYTES = 32
IV_BYTES = 12
TAG_BYTES = 16


class SecretEncryptionError(RuntimeError):
    pass


class SecretEncryptionKeyMissingError(SecretEncryptionError):
    pass


def configured() -> bool:
    key = os.environ.get(KEY_ENV)
    return bool(key and key.strip())


def is_encrypted(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encryption_key() -> bytes:
    raw = os.environ.get(KEY_ENV)
    if not raw or not raw.strip():
        raise SecretEncryptionKeyMissingError(
            f"{KEY_ENV} must be set to a 64 character hex string (openssl rand -hex 32) to store or read encrypted secrets"
        )
    raw = raw.strip()
    if not re.fullmatch(rf"[0-9a-fA-F]{{{KEY_BYTES * 2}}}", raw):
        raise SecretEncryptionError(f"{KEY_ENV} must be exactly {KEY_BYTES * 2} hex characters")
    return bytes.fromhex(raw)


def encrypt(plaintext: str, context: str) -> str:
    if not isinstance(plaintext, str):
        raise TypeError(f"plaintext must be a str but is a {type(plaintext).__name__}")
    iv = secrets.token_bytes(IV_BYTES)
    sealed = AESGCM(encryption_key()).encrypt(iv, plaintext.encode("utf-8"), str(context).encode("utf-8"))
    ciphertext, tag = sealed[:-TAG_BYTES], sealed[-TAG_BYTES:]
    return ":".join([PREFIX.rstrip(":"), _encode(iv), _encode(tag), _encode(ciphertext)])


def decrypt(value, context: str):
    if not is_encrypted(value):
        return value
    parts = value.split(":", 4)
    if len(parts) != 5:
        raise SecretEncryptionError(f"Malformed encrypted secret for {context}")
    _enc, _version, iv, tag, ciphertext = parts
    iv = _decode(iv)
    tag = _decode(tag)
    if len(iv) != IV_BYTES or len(tag) != TAG_BYTES:
        raise SecretEncryptionError(f"Malformed encrypted secret for {context}")
    try:
        plaintext = AESGCM(encryption_key()).decrypt(iv, _decode(ciphertext) + tag, str(context).encode("utf-8"))
    except InvalidTag as error:
        raise SecretEncryptionError(
            f"Unable to decrypt secret for {context}: wrong {KEY_ENV} or tampered value"
        ) from error
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return plaintext.decode("latin-1")


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as error:
        raise SecretEncryptionError("Malformed encrypted secret") from error

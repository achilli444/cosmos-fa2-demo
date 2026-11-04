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

"""Encrypts secret values before they are written to Redis and decrypts them
on the way back out, so a Redis dump, backup or read-only connection never
yields a usable credential. AES-256-GCM is an authenticated cipher, so a value
that was tampered with, or moved to a different secret name or scope, is
rejected instead of silently returned.

The key never lives in Redis. It is read from OPENC3_SECRETS_KEY (64 hex
characters = 32 bytes) or, preferably for mounted secrets, from the file named
by OPENC3_SECRETS_KEY_FILE (64 hex characters or 32 raw bytes).

The stored form is a dict so it can be told apart from a legacy plaintext str:
    {"v": 1, "alg": "aes-256-gcm", "iv": <b64>, "ct": <b64>, "tag": <b64>}
openc3/lib/openc3/utilities/secret_cipher.rb produces and consumes the same
format because Ruby and Python microservices share the secret store.
"""

import base64
import binascii
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretCipherKeyError(RuntimeError):
    pass


class SecretCipherDecryptError(RuntimeError):
    pass


class SecretCipher:
    ALGORITHM = "aes-256-gcm"
    VERSION = 1
    KEY_BYTES = 32
    IV_BYTES = 12
    TAG_BYTES = 16
    KEY_ENV = "OPENC3_SECRETS_KEY"
    KEY_FILE_ENV = "OPENC3_SECRETS_KEY_FILE"

    @classmethod
    def key(cls) -> bytes:
        """Returns the 32 byte key"""
        hex_key = os.environ.get(cls.KEY_ENV)
        if hex_key is None or not hex_key.strip():
            path = os.environ.get(cls.KEY_FILE_ENV)
            if path is None or not path.strip():
                raise SecretCipherKeyError(
                    f"{cls.KEY_ENV} or {cls.KEY_FILE_ENV} must be set: the redis secrets "
                    f"backend encrypts secret values at rest with {cls.ALGORITHM} "
                    f"(generate a key with 'openssl rand -hex {cls.KEY_BYTES}')"
                )
            try:
                with open(path, "rb") as f:
                    raw = f.read()
            except OSError as e:
                raise SecretCipherKeyError(f"Unable to read {cls.KEY_FILE_ENV} '{path}': {e}") from e
            if len(raw) == cls.KEY_BYTES:
                return raw
            hex_key = raw.decode("ascii", errors="replace")
        hex_key = hex_key.strip()
        if not re.fullmatch(rf"[0-9a-fA-F]{{{cls.KEY_BYTES * 2}}}", hex_key):
            raise SecretCipherKeyError(
                f"{cls.KEY_ENV} must be {cls.KEY_BYTES * 2} hex characters "
                f"({cls.KEY_BYTES} bytes), e.g. from 'openssl rand -hex {cls.KEY_BYTES}'"
            )
        return bytes.fromhex(hex_key)

    @classmethod
    def is_encrypted(cls, value) -> bool:
        """Whether value is an encrypted envelope produced by encrypt"""
        return isinstance(value, dict) and value.get("alg") == cls.ALGORITHM and "ct" in value

    @classmethod
    def encrypt(cls, plaintext: str, aad: str) -> dict:
        """Encrypts plaintext, binding it to aad (the secret's scope and name)
        so an envelope can't be reused elsewhere. Returns the envelope dict."""
        iv = os.urandom(cls.IV_BYTES)
        data = AESGCM(cls.key()).encrypt(iv, str(plaintext).encode("utf-8"), aad.encode("utf-8"))
        ciphertext, tag = data[: -cls.TAG_BYTES], data[-cls.TAG_BYTES :]
        return {
            "v": cls.VERSION,
            "alg": cls.ALGORITHM,
            "iv": base64.b64encode(iv).decode("ascii"),
            "ct": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }

    @classmethod
    def decrypt(cls, envelope: dict, aad: str) -> str:
        """Decrypts an envelope produced by encrypt; aad must match"""
        if not cls.is_encrypted(envelope):
            raise SecretCipherDecryptError(f"Secret value is not an {cls.ALGORITHM} envelope")
        try:
            iv = base64.b64decode(str(envelope.get("iv", "")), validate=True)
            ciphertext = base64.b64decode(str(envelope.get("ct", "")), validate=True)
            tag = base64.b64decode(str(envelope.get("tag", "")), validate=True)
        except (binascii.Error, ValueError) as e:
            raise SecretCipherDecryptError(f"Secret envelope is malformed: {e}") from e
        if len(iv) != cls.IV_BYTES or len(tag) != cls.TAG_BYTES:
            raise SecretCipherDecryptError("Secret envelope is malformed: bad iv or tag length")
        try:
            plaintext = AESGCM(cls.key()).decrypt(iv, ciphertext + tag, aad.encode("utf-8"))
        except InvalidTag as e:
            raise SecretCipherDecryptError(
                f"Secret could not be decrypted: wrong {cls.KEY_ENV} or tampered value"
            ) from e
        return plaintext.decode("utf-8")

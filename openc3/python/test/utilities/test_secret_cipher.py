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

import base64
import os
import tempfile
import unittest
from unittest.mock import patch

from openc3.utilities.secret_cipher import SecretCipher, SecretCipherDecryptError, SecretCipherKeyError


KEY_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
AAD = "DEFAULT__openc3__secrets:PW"


class TestSecretCipher(unittest.TestCase):
    def setUp(self):
        patcher = patch.dict(os.environ, {"OPENC3_SECRETS_KEY": KEY_HEX})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("OPENC3_SECRETS_KEY_FILE", None)

    def test_reads_hex_key_from_env(self):
        self.assertEqual(SecretCipher.key(), b"\x00" * 31 + b"\x01")

    def test_reads_hex_key_from_file(self):
        del os.environ["OPENC3_SECRETS_KEY"]
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(KEY_HEX + "\n")
        self.addCleanup(os.unlink, f.name)
        os.environ["OPENC3_SECRETS_KEY_FILE"] = f.name
        self.assertEqual(SecretCipher.key(), b"\x00" * 31 + b"\x01")

    def test_reads_raw_key_from_file(self):
        del os.environ["OPENC3_SECRETS_KEY"]
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"\xab" * 32)
        self.addCleanup(os.unlink, f.name)
        os.environ["OPENC3_SECRETS_KEY_FILE"] = f.name
        self.assertEqual(SecretCipher.key(), b"\xab" * 32)

    def test_fails_closed_without_key(self):
        del os.environ["OPENC3_SECRETS_KEY"]
        with self.assertRaisesRegex(SecretCipherKeyError, "OPENC3_SECRETS_KEY or OPENC3_SECRETS_KEY_FILE must be set"):
            SecretCipher.key()
        os.environ["OPENC3_SECRETS_KEY"] = ""
        with self.assertRaises(SecretCipherKeyError):
            SecretCipher.encrypt("x", aad=AAD)

    def test_rejects_bad_key(self):
        os.environ["OPENC3_SECRETS_KEY"] = "abc"
        with self.assertRaisesRegex(SecretCipherKeyError, "64 hex characters"):
            SecretCipher.key()
        os.environ["OPENC3_SECRETS_KEY"] = "zz" * 32
        with self.assertRaisesRegex(SecretCipherKeyError, "64 hex characters"):
            SecretCipher.key()

    def test_reports_unreadable_key_file(self):
        del os.environ["OPENC3_SECRETS_KEY"]
        os.environ["OPENC3_SECRETS_KEY_FILE"] = "/nonexistent/openc3_key"
        with self.assertRaisesRegex(SecretCipherKeyError, "Unable to read"):
            SecretCipher.key()

    def test_round_trip_never_stores_plaintext(self):
        envelope = SecretCipher.encrypt("hunter2", aad=AAD)
        self.assertEqual(envelope["alg"], "aes-256-gcm")
        self.assertEqual(envelope["v"], 1)
        self.assertNotIn("hunter2", "".join(str(v) for v in envelope.values()))
        self.assertEqual(len(base64.b64decode(envelope["iv"])), 12)
        self.assertEqual(len(base64.b64decode(envelope["tag"])), 16)
        self.assertEqual(SecretCipher.decrypt(envelope, aad=AAD), "hunter2")

    def test_fresh_iv_each_time(self):
        a = SecretCipher.encrypt("same", aad=AAD)
        b = SecretCipher.encrypt("same", aad=AAD)
        self.assertNotEqual(a["iv"], b["iv"])
        self.assertNotEqual(a["ct"], b["ct"])

    def test_empty_and_multibyte(self):
        self.assertEqual(SecretCipher.decrypt(SecretCipher.encrypt("", aad=AAD), aad=AAD), "")
        self.assertEqual(
            SecretCipher.decrypt(SecretCipher.encrypt("pässwörd\u00e9", aad=AAD), aad=AAD), "pässwörd\u00e9"
        )

    def test_rejects_tampered_ciphertext(self):
        envelope = SecretCipher.encrypt("hunter2", aad=AAD)
        ct = bytearray(base64.b64decode(envelope["ct"]))
        ct[0] ^= 0xFF
        envelope["ct"] = base64.b64encode(bytes(ct)).decode()
        with self.assertRaisesRegex(SecretCipherDecryptError, "tampered"):
            SecretCipher.decrypt(envelope, aad=AAD)

    def test_rejects_moved_ciphertext(self):
        envelope = SecretCipher.encrypt("hunter2", aad=AAD)
        with self.assertRaises(SecretCipherDecryptError):
            SecretCipher.decrypt(envelope, aad="DEFAULT__openc3__secrets:OTHER")
        with self.assertRaises(SecretCipherDecryptError):
            SecretCipher.decrypt(envelope, aad="OTHER__openc3__secrets:PW")

    def test_rejects_wrong_key(self):
        envelope = SecretCipher.encrypt("hunter2", aad=AAD)
        os.environ["OPENC3_SECRETS_KEY"] = "ff" * 32
        with self.assertRaisesRegex(SecretCipherDecryptError, "wrong OPENC3_SECRETS_KEY"):
            SecretCipher.decrypt(envelope, aad=AAD)

    def test_rejects_malformed_envelopes(self):
        with self.assertRaisesRegex(SecretCipherDecryptError, "not an aes-256-gcm envelope"):
            SecretCipher.decrypt("plaintext", aad=AAD)
        envelope = SecretCipher.encrypt("hunter2", aad=AAD)
        with self.assertRaisesRegex(SecretCipherDecryptError, "malformed"):
            SecretCipher.decrypt({**envelope, "iv": "!!"}, aad=AAD)
        with self.assertRaisesRegex(SecretCipherDecryptError, "malformed"):
            SecretCipher.decrypt({**envelope, "tag": base64.b64encode(b"short").decode()}, aad=AAD)

    def test_decrypts_ruby_envelope(self):
        # Generated by openc3/lib/openc3/utilities/secret_cipher.rb with KEY_HEX
        envelope = {
            "v": 1,
            "alg": "aes-256-gcm",
            "iv": "YFitVfdPFiWYSyGL",
            "ct": "30dwP8XKcw==",
            "tag": "tOQFn6uUZvHHzsbhwfmogw==",
        }
        self.assertEqual(SecretCipher.decrypt(envelope, aad=AAD), "hunter2")

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.

import hashlib
import unittest

from openc3.models.bridge_model import BridgeModel


class TestBridgeModel(unittest.TestCase):
    def test_enrollment_code_is_valid_only_within_ttl(self):
        model = BridgeModel(
            name="LAB1",
            scope="DEFAULT",
            enroll_code_hash=BridgeModel.hash_enrollment_code("one-time-code"),
            enroll_code_generated_at=1_000,
        )

        self.assertTrue(model.enrollment_code_valid("one-time-code", 1_000))
        self.assertTrue(model.enrollment_code_valid("one-time-code", 1_000 + BridgeModel.ENROLLMENT_CODE_TTL_SECONDS))
        self.assertFalse(model.enrollment_code_valid("one-time-code", 1_001 + BridgeModel.ENROLLMENT_CODE_TTL_SECONDS))
        self.assertFalse(model.enrollment_code_valid("wrong-code", 1_001))
        self.assertFalse(model.enrollment_code_valid(None, 1_001))
        self.assertFalse(model.enrollment_code_valid(["one-time-code"], 1_001))

    def test_hash_matches_ruby_sha256_hex(self):
        self.assertEqual(
            BridgeModel.hash_enrollment_code("one-time-code"),
            hashlib.sha256(b"one-time-code").hexdigest(),
        )

    def test_as_json_never_contains_the_plaintext_code(self):
        model = BridgeModel(
            name="LAB1",
            scope="DEFAULT",
            enroll_code_hash=BridgeModel.hash_enrollment_code("one-time-code"),
            enroll_code_generated_at=1_000,
        )
        as_json = model.as_json()
        self.assertNotIn("enroll_code", as_json)
        self.assertEqual(as_json["enroll_code_hash"], BridgeModel.hash_enrollment_code("one-time-code"))
        self.assertNotIn("one-time-code", str(as_json))

    def test_enrollment_codes_without_a_timestamp_fail_closed(self):
        model = BridgeModel(
            name="LAB1", scope="DEFAULT", enroll_code_hash=BridgeModel.hash_enrollment_code("legacy-code")
        )

        self.assertFalse(model.enrollment_code_valid("legacy-code", 1_000))
        self.assertTrue(model.enrollment_code_expired(1_000))

    def test_legacy_plaintext_records_fail_closed_and_drop_the_plaintext(self):
        model = BridgeModel.from_json(
            {"name": "LAB1", "scope": "DEFAULT", "enroll_code": "legacy-code", "enroll_code_generated_at": 1_000},
            "DEFAULT",
        )

        self.assertFalse(model.enrollment_code_valid("legacy-code", 1_000))
        self.assertNotIn("enroll_code", model.as_json())
        self.assertNotIn("legacy-code", str(model.as_json()))

    def test_expired_detection_and_clear(self):
        model = BridgeModel(
            name="LAB1",
            scope="DEFAULT",
            enroll_code_hash=BridgeModel.hash_enrollment_code("one-time-code"),
            enroll_code_generated_at=1_000,
        )
        self.assertFalse(model.enrollment_code_expired(1_000 + BridgeModel.ENROLLMENT_CODE_TTL_SECONDS))
        self.assertTrue(model.enrollment_code_expired(1_001 + BridgeModel.ENROLLMENT_CODE_TTL_SECONDS))

        model.clear_enrollment_code()
        self.assertIsNone(model.enroll_code_hash)
        self.assertIsNone(model.enroll_code_generated_at)
        self.assertFalse(model.enrollment_code_expired(2_000))
        self.assertFalse(model.enrollment_code_valid("one-time-code", 1_000))


if __name__ == "__main__":
    unittest.main()

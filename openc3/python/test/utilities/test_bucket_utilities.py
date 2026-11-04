# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software; you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

import hashlib
import hmac
import os
import tempfile
import unittest
from unittest.mock import Mock

from openc3.utilities.bucket_utilities import BucketUtilities


class TestBucketUtilitiesIntegrity(unittest.TestCase):
    KEY = "DEFAULT/raw_logs/tlm/INST/20260101/20260101000000000000000__20260101001000000000000.bin.gz"

    def setUp(self):
        self.saved = os.environ.pop("OPENC3_LOG_INTEGRITY_KEY", None)
        fd, self.filename = tempfile.mkstemp(suffix=".bin.gz")
        with os.fdopen(fd, "wb") as file:
            file.write(b"telemetry log contents")

    def tearDown(self):
        if self.saved is not None:
            os.environ["OPENC3_LOG_INTEGRITY_KEY"] = self.saved
        os.unlink(self.filename)

    def test_sha256_metadata_by_default(self):
        expected = hashlib.sha256(b"telemetry log contents").hexdigest()
        self.assertEqual(
            BucketUtilities.integrity_metadata(self.filename),
            {"log-digest": expected, "log-digest-algorithm": "sha256"},
        )

    def test_hmac_metadata_with_key(self):
        os.environ["OPENC3_LOG_INTEGRITY_KEY"] = "managed-key"
        expected = hmac.new(b"managed-key", b"telemetry log contents", hashlib.sha256).hexdigest()
        self.assertEqual(
            BucketUtilities.integrity_metadata(self.filename),
            {"log-digest": expected, "log-digest-algorithm": "hmac-sha256"},
        )

    def test_index_key_matches_ruby_layout(self):
        self.assertEqual(
            BucketUtilities.integrity_index_key(self.KEY),
            "DEFAULT/log_integrity/raw_logs/tlm/INST/20260101/20260101000000000000000__20260101001000000000000.bin.gz.sha256",
        )
        self.assertEqual(BucketUtilities.integrity_index_key("orphan.txt"), "log_integrity/orphan.txt.sha256")

    def test_write_integrity_index(self):
        client = Mock()
        metadata = BucketUtilities.integrity_metadata(self.filename)
        BucketUtilities.write_integrity_index(client, "logs", self.KEY, metadata)
        client.put_object.assert_called_once()
        kwargs = client.put_object.call_args.kwargs
        self.assertEqual(kwargs["bucket"], "logs")
        self.assertEqual(kwargs["key"], BucketUtilities.integrity_index_key(self.KEY))
        self.assertEqual(kwargs["metadata"], metadata)
        self.assertTrue(kwargs["body"].decode().startswith(f"sha256  {metadata['log-digest']}  {self.KEY}  "))

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

import hashlib
import hmac
import os
import threading
import time
import zlib
from datetime import datetime, timezone

from openc3.environment import OPENC3_LOGS_BUCKET
from openc3.utilities.bucket import Bucket
from openc3.utilities.logger import Logger


class BucketUtilities:
    FILE_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S%N"
    DIRECTORY_TIMESTAMP_FORMAT = "%Y%m%d"

    # Log integrity metadata, same layout as the Ruby OpenC3::LogIntegrity module (AU-9(3))
    DIGEST_METADATA_KEY = "log-digest"
    ALGORITHM_METADATA_KEY = "log-digest-algorithm"
    INDEX_DIRECTORY = "log_integrity"
    INDEX_SUFFIX = ".sha256"
    DIGEST_CHUNK_SIZE = 50_000_000

    @classmethod
    def integrity_key(cls):
        return os.environ.get("OPENC3_LOG_INTEGRITY_KEY") or None

    @classmethod
    def integrity_algorithm(cls):
        return "hmac-sha256" if cls.integrity_key() else "sha256"

    @classmethod
    def digest_file(cls, filename, algorithm=None):
        algorithm = algorithm or cls.integrity_algorithm()
        if algorithm == "hmac-sha256":
            key = cls.integrity_key()
            if not key:
                raise ValueError("hmac-sha256 digest requested but OPENC3_LOG_INTEGRITY_KEY is not set")
            digest = hmac.new(key.encode(), digestmod=hashlib.sha256)
        elif algorithm == "sha256":
            digest = hashlib.sha256()
        else:
            raise ValueError(f"Unknown log digest algorithm: {algorithm}")
        with open(filename, "rb") as file:
            while True:
                chunk = file.read(cls.DIGEST_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    @classmethod
    def integrity_metadata(cls, filename):
        algorithm = cls.integrity_algorithm()
        return {
            cls.DIGEST_METADATA_KEY: cls.digest_file(filename, algorithm),
            cls.ALGORITHM_METADATA_KEY: algorithm,
        }

    @classmethod
    def integrity_index_key(cls, bucket_key):
        parts = bucket_key.split("/", 1)
        if len(parts) == 1:
            return f"{cls.INDEX_DIRECTORY}/{parts[0]}{cls.INDEX_SUFFIX}"
        return f"{parts[0]}/{cls.INDEX_DIRECTORY}/{parts[1]}{cls.INDEX_SUFFIX}"

    @classmethod
    def integrity_index_record(cls, bucket_key, metadata):
        now = datetime.now(timezone.utc).isoformat()
        return f"{metadata[cls.ALGORITHM_METADATA_KEY]}  {metadata[cls.DIGEST_METADATA_KEY]}  {bucket_key}  {now}\n"

    @classmethod
    def write_integrity_index(cls, client, bucket, bucket_key, metadata):
        client.put_object(
            bucket=bucket,
            key=cls.integrity_index_key(bucket_key),
            body=cls.integrity_index_record(bucket_key, metadata).encode(),
            content_type="text/plain",
            metadata=metadata,
        )

    # TODO: This is never called
    # @classmethod
    # def bucket_load(cls, *args, scope=OPENC3_SCOPE):
    #     if not scope:
    #         scope = OPENC3_SCOPE
    #     path = args[0]

    #     # Only support TARGET files
    #     if path[0] == "/" or str(path.split("/")[0]).upper() != path.split("/")[0]:
    #         raise ImportError(f"only relative TARGET files are allowed -- {path}")
    #     extension = os.path.splitext(path)[1]
    #     if not extension or extension == "":
    #         path = path + ".py"

    #     # Retrieve the text of the script from S3
    #     text = TargetFile.body(scope, path)
    #     if not text:
    #         raise ImportError(f"Bucket file {path} not found for scope {scope}")

    #     # Execute the script directly without instrumentation because we are doing require/load
    #     exec(text.decode())

    #     # Successful load/require returns true
    #     return True

    @classmethod
    def move_log_file_to_bucket_thread(cls, filename, bucket_key, metadata=None):
        if metadata is None:
            metadata = {}
        try:
            client = Bucket.get_client()

            orig_filename = None
            if os.path.splitext(filename)[1] != ".txt":
                orig_filename = filename
                filename = cls.compress_file(filename)
                bucket_key += ".gz"

            # Digest the exact bytes being uploaded so the stored object can be verified on read (AU-9(3))
            integrity = cls.integrity_metadata(filename)
            metadata = {**metadata, **integrity}

            retry_count = 0
            while retry_count < 3:
                try:
                    # We want to open this as a file and pass that to put_object to allow
                    # this to work with really large files. Otherwise the entire file has
                    # to be held in memory!
                    with open(filename, "rb") as file:
                        client.put_object(
                            bucket=OPENC3_LOGS_BUCKET,
                            key=bucket_key,
                            body=file,
                            metadata=metadata,
                        )
                    cls.write_integrity_index(client, OPENC3_LOGS_BUCKET, bucket_key, integrity)
                    break
                except Exception as err:
                    # Try to upload file three times
                    retry_count += 1
                    if retry_count >= 3:
                        raise err
                    Logger.warn(f"Error saving log file to bucket - retry {retry_count}: {filename}\n{str(err)}")
                    time.sleep(1)

            Logger.debug(f"wrote {OPENC3_LOGS_BUCKET}/{bucket_key}")

            if orig_filename:
                os.remove(orig_filename)
            os.remove(filename)
        except Exception as err:
            Logger.error(f"Error saving log file to bucket: {filename}\n{str(err)}")

    @classmethod
    def move_log_file_to_bucket(cls, filename, bucket_key, metadata=None):
        if metadata is None:
            metadata = {}
        thread = threading.Thread(
            target=cls.move_log_file_to_bucket_thread,
            args=[filename, bucket_key, metadata],
            daemon=True,
        )
        thread.start()
        return thread

    @classmethod
    def compress_file(cls, filename, chunk_size=50_000_000):
        zipped = f"{filename}.gz"

        obj = zlib.compressobj()
        with open(zipped, "wb") as zip_file, open(filename, "rb") as file:
            while True:
                chunk = file.read(chunk_size)
                if chunk:
                    compressed = obj.compress(chunk)
                    zip_file.write(compressed)
                else:
                    compressed = obj.flush()
                    if compressed:
                        zip_file.write(compressed)
                    break

        return zipped

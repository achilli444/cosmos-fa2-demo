# encoding: ascii-8bit

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

require 'openssl'
require 'openc3/utilities/logger'
require 'openc3/utilities/bucket'

module OpenC3
  # Integrity protection for log files stored in the logs bucket (NIST 800-53 AU-9, AU-9(3)).
  #
  # When a log file is moved to the bucket a SHA-256 digest (or an HMAC-SHA256 when
  # OPENC3_LOG_INTEGRITY_KEY is set) of the exact bytes uploaded is computed and stored in
  # two places: the object metadata and a write-once index record under
  # <scope>/log_integrity/... in the same bucket. Readers call verify_object before using
  # a downloaded log so modification or replacement of a stored log is detected.
  module LogIntegrity
    class IntegrityError < StandardError; end

    DIGEST_METADATA_KEY = 'log-digest'
    ALGORITHM_METADATA_KEY = 'log-digest-algorithm'
    INDEX_DIRECTORY = 'log_integrity'
    INDEX_SUFFIX = '.sha256'
    SHA256 = 'sha256'
    HMAC_SHA256 = 'hmac-sha256'
    CHUNK_SIZE = 50_000_000

    def self.key
      value = ENV.fetch('OPENC3_LOG_INTEGRITY_KEY', nil)
      return nil if value.nil? or value.empty?
      value
    end

    def self.algorithm
      key() ? HMAC_SHA256 : SHA256
    end

    # Reading of logs written before integrity protection was enabled (no digest metadata)
    # is allowed with a warning unless OPENC3_LOG_INTEGRITY_REQUIRED is set
    def self.required?
      value = ENV.fetch('OPENC3_LOG_INTEGRITY_REQUIRED', nil)
      return false if value.nil? or value.empty?
      !%w[0 false no].include?(value.downcase)
    end

    # @param path [String] Local file to digest
    # @param algorithm [String] SHA256 or HMAC_SHA256 (defaults to the configured algorithm)
    # @return [String] Hex digest of the file contents
    def self.digest_file(path, algorithm = self.algorithm)
      digest = new_digest(algorithm)
      File.open(path, 'rb') do |file|
        while (chunk = file.read(CHUNK_SIZE))
          digest.update(chunk)
        end
      end
      digest.hexdigest
    end

    # Metadata to store alongside the uploaded object
    def self.metadata_for(path)
      algorithm = self.algorithm
      { DIGEST_METADATA_KEY => digest_file(path, algorithm), ALGORITHM_METADATA_KEY => algorithm }
    end

    # Key of the write-once index record for a log object. The record lives under a separate
    # prefix (<scope>/log_integrity/...) so bucket policy can grant it narrower permissions
    # than the log data itself.
    def self.index_key(bucket_key)
      scope, rest = bucket_key.split('/', 2)
      return "#{INDEX_DIRECTORY}/#{scope}#{INDEX_SUFFIX}" unless rest
      "#{scope}/#{INDEX_DIRECTORY}/#{rest}#{INDEX_SUFFIX}"
    end

    # One line in the style of sha256sum plus the algorithm and the time the record was made
    def self.index_record(bucket_key, metadata)
      "#{metadata[ALGORITHM_METADATA_KEY]}  #{metadata[DIGEST_METADATA_KEY]}  #{bucket_key}  #{Time.now.utc.iso8601(9)}\n"
    end

    def self.write_index(client, bucket, bucket_key, metadata)
      client.put_object(bucket: bucket, key: index_key(bucket_key), body: index_record(bucket_key, metadata),
                        content_type: 'text/plain', metadata: metadata)
    end

    # Verify a downloaded object against its stored digest.
    # @param client [Bucket] Bucket client
    # @param bucket [String] Bucket name
    # @param key [String] Object key that was downloaded
    # @param local_path [String] Path to the downloaded (still compressed) object
    # @return [Boolean] true if verified, false if no digest is stored (legacy object)
    # @raise [IntegrityError] if the digest does not match or is required and missing
    def self.verify_object(client, bucket, key, local_path)
      metadata = stored_metadata(client, bucket, key)
      expected = metadata[DIGEST_METADATA_KEY]
      algorithm = metadata[ALGORITHM_METADATA_KEY] || SHA256
      if expected.nil? or expected.empty?
        message = "No integrity digest stored for #{bucket}/#{key}"
        raise IntegrityError, message if required?
        Logger.warn("#{message}; written before integrity protection was enabled?")
        return false
      end
      verify_file(local_path, expected, algorithm, "#{bucket}/#{key}")
      index = index_digest(client, bucket, key)
      if index and index != expected
        raise IntegrityError, "Integrity index record for #{bucket}/#{key} (#{index}) does not match object metadata (#{expected})"
      end
      Logger.debug("Verified #{algorithm} of #{bucket}/#{key}")
      true
    end

    def self.verify_file(local_path, expected, algorithm, description = local_path)
      actual = digest_file(local_path, algorithm)
      unless secure_compare(actual, expected)
        raise IntegrityError, "Integrity check failed for #{description}: expected #{algorithm} #{expected} got #{actual}"
      end
      true
    end

    # Metadata keys are lowercased by S3 so accept either form
    def self.stored_metadata(client, bucket, key)
      head = client.head_object(bucket: bucket, key: key)
      metadata = head.respond_to?(:metadata) ? head.metadata : (head['metadata'] || head[:metadata])
      result = {}
      (metadata || {}).each { |k, v| result[k.to_s.downcase] = v }
      result
    rescue Bucket::NotFound
      {}
    end

    def self.index_digest(client, bucket, key)
      object = client.get_object(bucket: bucket, key: index_key(key))
      return nil unless object
      body = object.respond_to?(:body) ? object.body : object[:body]
      body = body.read if body.respond_to?(:read)
      body.to_s.split(/\s+/)[1]
    rescue Bucket::NotFound
      nil
    end

    def self.new_digest(algorithm)
      case algorithm
      when HMAC_SHA256
        hmac_key = key()
        raise IntegrityError, "#{HMAC_SHA256} digest requested but OPENC3_LOG_INTEGRITY_KEY is not set" unless hmac_key
        OpenSSL::HMAC.new(hmac_key, OpenSSL::Digest.new('SHA256'))
      when SHA256
        OpenSSL::Digest.new('SHA256')
      else
        raise IntegrityError, "Unknown log digest algorithm: #{algorithm}"
      end
    end

    def self.secure_compare(a, b)
      return false unless a.bytesize == b.bytesize
      OpenSSL.fixed_length_secure_compare(a, b)
    end
  end
end

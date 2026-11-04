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

require 'openc3/utilities/bucket_utilities'
require 'openc3/utilities/logger'

module OpenC3
  # Minimum retention floor for the command / telemetry records kept in the
  # logs bucket. Every path that destroys those records (the Storage API and
  # the per-target CleanupMicroservice) must go through this module so that
  # nothing younger than OPENC3_LOG_MIN_RETAIN_TIME seconds is deleted and
  # every deletion leaves an info-level audit record.
  module LogRetention
    class RetentionError < StandardError; end

    ENV_VAR = 'OPENC3_LOG_MIN_RETAIN_TIME'
    # {SCOPE}/raw_logs/cmd/..., {SCOPE}/raw_logs/tlm/..., {SCOPE}/decom_logs/...
    PROTECTED_KEY = %r{\A[^/]+/(raw_logs/(cmd|tlm)|decom_logs)/}

    # @return [Integer] Minimum retention period in seconds
    # @raise [RetentionError] when the floor is unset or invalid (fail closed)
    def self.minimum_retain_time
      value = ENV.fetch(ENV_VAR, '').strip
      unless value.match?(/\A\d+\z/)
        raise RetentionError, "#{ENV_VAR} must be set to the minimum number of seconds to retain cmd/tlm logs before they can be deleted"
      end

      value.to_i
    end

    # @return [Time] Newest file end time that may currently be deleted
    def self.cutoff(now: Time.now)
      now - minimum_retain_time
    end

    # @return [Boolean] Whether the key holds cmd/tlm records covered by the floor
    def self.protected_key?(key)
      PROTECTED_KEY.match?(key.to_s)
    end

    # @return [Time, nil] Time of the last record in the log file, nil if the
    #   key does not carry the START__END timestamp log file naming convention
    def self.file_end_time(key)
      _, end_time = BucketUtilities.get_file_times(key)
      end_time
    rescue StandardError
      nil
    end

    # Protected keys are deletable only when every record they hold is older
    # than the cutoff. A protected key whose age cannot be determined is kept.
    # @return [Boolean]
    def self.deletable?(key, cutoff)
      return true unless protected_key?(key)

      end_time = file_end_time(key)
      return false unless end_time

      end_time <= cutoff
    end

    # @param keys [Array<String>] Bucket keys about to be deleted
    # @return [Time] The cutoff the keys were checked against
    # @raise [RetentionError] if any key is still inside the retention floor
    def self.check_deletable!(keys, now: Time.now)
      cutoff = cutoff(now: now)
      retained = keys.reject { |key| deletable?(key, cutoff) }
      unless retained.empty?
        shown = retained.first(5).join(', ')
        shown += ", ... (#{retained.length} total)" if retained.length > 5
        raise RetentionError, "Refusing to delete #{retained.length} cmd/tlm log object(s) newer than the #{ENV_VAR} cutoff #{cutoff.utc.iso8601}: #{shown}"
      end
      cutoff
    end

    # Durable record of a cmd/tlm log deletion
    def self.audit(bucket:, prefix:, cutoff:, keys:, scope:, user: nil, logger: Logger)
      logger.info("Log retention delete: #{bucket}/#{prefix} #{keys.length} object(s) older than #{cutoff.utc.iso8601}: #{keys.join(', ')}",
                  scope: scope, user: user)
    end
  end
end

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

require 'openc3/utilities/logger'

module OpenC3
  # Minimum retention for objects in the logs bucket (NIST 800-53 AU-9, AU-11, SI-12).
  #
  # OPENC3_LOG_MIN_RETAIN_TIME (seconds) is the organization-defined floor. Per-target and
  # per-scope *_RETAIN_TIME settings below it are raised to it by the cleanup microservices,
  # and the storage API refuses to delete logs bucket objects younger than it.
  # Unset or 0 means no floor is enforced.
  module LogRetention
    ENV_VAR = 'OPENC3_LOG_MIN_RETAIN_TIME'

    # @return [Integer] Minimum retention in seconds, 0 when not configured
    def self.minimum_retain_time
      value = ENV.fetch(ENV_VAR, nil)
      return 0 if value.nil? or value.strip.empty?
      value.to_i
    end

    # @param retain_time [Integer|nil] Configured retention in seconds (nil means never delete)
    # @param prefix [String] Log prefix being cleaned up, for the warning
    # @return [Integer|nil] Retention actually applied
    def self.effective_retain_time(retain_time, prefix: nil, logger: Logger)
      return nil if retain_time.nil?
      minimum = minimum_retain_time()
      if minimum > 0 and retain_time < minimum
        logger.warn("Retain time #{retain_time}s for #{prefix} is below the minimum #{minimum}s (#{ENV_VAR}); using the minimum")
        return minimum
      end
      retain_time
    end

    # @return [Boolean] Whether the bucket parameter names the logs bucket
    def self.logs_bucket?(bucket_param)
      bucket_param.to_s == 'OPENC3_LOGS_BUCKET'
    end

    # Whether an object in the logs bucket is still inside the minimum retention period.
    # An object whose age cannot be determined is treated as retained.
    # @param last_modified [Time|nil] When the object was written
    def self.retained?(last_modified, now: Time.now)
      minimum = minimum_retain_time()
      return false if minimum <= 0
      return true if last_modified.nil?
      last_modified.to_time > (now - minimum)
    end
  end
end

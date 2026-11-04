# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/models/target_model'
require 'openc3/microservices/microservice'
require 'openc3/utilities/bucket'
require 'openc3/utilities/bucket_utilities'
require 'openc3/utilities/log_retention'

module OpenC3
  class CleanupMicroservice < Microservice
    def initialize(*args)
      super(*args)
      @metric.set(name: 'cleanup_total', value: @count, type: 'counter')
      @delete_count = 0
      @metric.set(name: 'cleanup_delete_total', value: @delete_count, type: 'counter')
      @sleeper = Sleeper.new
    end

    def cleanup(areas, bucket)
      @state = 'GETTING_OBJECTS'
      start_time = Time.now
      begin
        min_retain_time = LogRetention.minimum_retain_time
      rescue LogRetention::RetentionError => e
        # Fail closed: without a retention floor nothing is deleted
        @logger.error("Cleanup skipped: #{e.message}")
        return
      end
      logs_bucket = ENV['OPENC3_LOGS_BUCKET']
      areas.each do |prefix, retain_time|
        next unless retain_time
        if retain_time < min_retain_time
          @logger.warn("Cleanup retain time #{retain_time}s for #{prefix} is below the #{LogRetention::ENV_VAR} floor, using #{min_retain_time}s")
          retain_time = min_retain_time
        end
        time = start_time - retain_time
        oldest_list = BucketUtilities.files_between_time(logs_bucket, prefix, nil, time)
        if oldest_list.length > 0
          @state = 'DELETING_OBJECTS'
          oldest_list.each_slice(1000) do |slice|
            # Never trust the listing alone: re-check every key against the floor
            begin
              LogRetention.check_deletable!(slice, now: start_time)
            rescue LogRetention::RetentionError => e
              @logger.error("Cleanup skipped #{slice.length} objects under #{prefix}: #{e.message}")
              next
            end
            # The delete_objects function utilizes an MD5 hash when verifying the checksums, which is not
            # FIPS compliant (https://github.com/aws/aws-sdk-ruby/issues/2645).
            # delete_object does NOT require an MD5 hash and will work on FIPS compliant systems. It is
            # probably less performant, but we can instead delete each item one at a time.
            # bucket.delete_objects(bucket: ENV['OPENC3_LOGS_BUCKET'], keys: slice)
            slice.each do |item|
              bucket.delete_object(bucket: logs_bucket, key: item)
            end
            LogRetention.audit(bucket: logs_bucket, prefix: prefix, cutoff: time, keys: slice,
                               scope: @scope, logger: @logger)
            @delete_count += slice.length
            @metric.set(name: 'cleanup_delete_total', value: @delete_count, type: 'counter')
          end
        end
      end
    end

    def get_areas_and_poll_time
      split_name = @name.split("__")
      target_name = split_name[-1]
      target = TargetModel.get_model(name: target_name, scope: @scope)

      areas = [
        ["#{@scope}/raw_logs/cmd/#{target_name}", target.cmd_log_retain_time],
        ["#{@scope}/raw_logs/tlm/#{target_name}", target.tlm_log_retain_time],
      ]
      return areas, target.cleanup_poll_time
    end

    def run
      bucket = Bucket.getClient()
      while true
        break if @cancel_thread
        areas, poll_time = get_areas_and_poll_time()
        cleanup(areas, bucket)

        @count += 1
        @metric.set(name: 'cleanup_total', value: @count, type: 'counter')

        @state = 'SLEEPING'
        break if @sleeper.sleep(poll_time)
      end
    end

    def shutdown
      @sleeper.cancel
      super()
    end
  end
end

if __FILE__ == $0
  OpenC3::CleanupMicroservice.run
  OpenC3::ThreadManager.instance.shutdown
  OpenC3::ThreadManager.instance.join
end

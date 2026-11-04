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

require 'spec_helper'
require 'openc3/microservices/cleanup_microservice'

module OpenC3
  describe CleanupMicroservice do
    let(:day) { 86_400 }

    def log_key(start_time, end_time)
      dir = start_time.strftime(BucketUtilities::DIRECTORY_TIMESTAMP_FORMAT)
      "DEFAULT/raw_logs/cmd/INST/#{dir}/#{start_time.strftime(BucketUtilities::FILE_TIMESTAMP_FORMAT)}__#{end_time.strftime(BucketUtilities::FILE_TIMESTAMP_FORMAT)}__DEFAULT__INST__ALL__rt__raw.bin.gz"
    end

    before(:each) do
      @saved = ENV.fetch(LogRetention::ENV_VAR, nil)
      ENV[LogRetention::ENV_VAR] = (7 * day).to_s
      ENV['OPENC3_LOGS_BUCKET'] = 'logs'
      @logger = double("Logger", debug: nil, info: nil, warn: nil, error: nil)
      @bucket = double("Bucket", delete_object: nil)
      # Skip Microservice#initialize (Redis, metrics thread, bucket wait)
      @ms = CleanupMicroservice.allocate
      @ms.instance_variable_set(:@logger, @logger)
      @ms.instance_variable_set(:@metric, double("Metric", set: nil))
      @ms.instance_variable_set(:@scope, 'DEFAULT')
      @ms.instance_variable_set(:@delete_count, 0)
      @now = Time.now
      allow(Time).to receive(:now).and_return(@now)
    end

    after(:each) do
      if @saved.nil?
        ENV.delete(LogRetention::ENV_VAR)
      else
        ENV[LogRetention::ENV_VAR] = @saved
      end
    end

    describe "cleanup" do
      it "deletes nothing and logs an error when the retention floor is unset" do
        ENV.delete(LogRetention::ENV_VAR)
        expect(BucketUtilities).not_to receive(:files_between_time)
        expect(@bucket).not_to receive(:delete_object)
        expect(@logger).to receive(:error).with(/Cleanup skipped: OPENC3_LOG_MIN_RETAIN_TIME must be set/)
        @ms.cleanup([["DEFAULT/raw_logs/cmd/INST", day]], @bucket)
      end

      it "raises a target retain time below the floor up to the floor" do
        expect(BucketUtilities).to receive(:files_between_time).with('logs', "DEFAULT/raw_logs/cmd/INST", nil, @now - (7 * day)).and_return([])
        expect(@logger).to receive(:warn).with(/below the OPENC3_LOG_MIN_RETAIN_TIME floor, using 604800s/)
        @ms.cleanup([["DEFAULT/raw_logs/cmd/INST", day]], @bucket)
      end

      it "keeps a target retain time above the floor" do
        expect(BucketUtilities).to receive(:files_between_time).with('logs', "DEFAULT/raw_logs/tlm/INST", nil, @now - (30 * day)).and_return([])
        expect(@logger).not_to receive(:warn)
        @ms.cleanup([["DEFAULT/raw_logs/tlm/INST", 30 * day]], @bucket)
      end

      it "skips areas without a retain time" do
        expect(BucketUtilities).not_to receive(:files_between_time)
        @ms.cleanup([["DEFAULT/raw_logs/cmd/INST", nil]], @bucket)
      end

      it "deletes expired files and records prefix, cutoff and keys at info level" do
        keys = [log_key(@now - (10 * day), @now - (9 * day)), log_key(@now - (9 * day), @now - (8 * day))]
        allow(BucketUtilities).to receive(:files_between_time).and_return(keys)
        keys.each { |key| expect(@bucket).to receive(:delete_object).with(bucket: 'logs', key: key) }
        cutoff = (@now - (7 * day)).utc.iso8601
        expect(@logger).to receive(:info).with(/Log retention delete: logs\/DEFAULT\/raw_logs\/cmd\/INST 2 object\(s\) older than #{Regexp.escape(cutoff)}: #{Regexp.escape(keys.join(', '))}/, scope: 'DEFAULT', user: nil)
        @ms.cleanup([["DEFAULT/raw_logs/cmd/INST", 7 * day]], @bucket)
        expect(@ms.instance_variable_get(:@delete_count)).to eq(2)
      end

      it "refuses a batch that still contains a file inside the floor" do
        keys = [log_key(@now - (10 * day), @now - (9 * day)), log_key(@now - (8 * day), @now - (6 * day))]
        allow(BucketUtilities).to receive(:files_between_time).and_return(keys)
        expect(@bucket).not_to receive(:delete_object)
        expect(@logger).to receive(:error).with(/Cleanup skipped 2 objects under DEFAULT\/raw_logs\/cmd\/INST: Refusing to delete 1/)
        @ms.cleanup([["DEFAULT/raw_logs/cmd/INST", 7 * day]], @bucket)
        expect(@ms.instance_variable_get(:@delete_count)).to eq(0)
      end
    end
  end
end

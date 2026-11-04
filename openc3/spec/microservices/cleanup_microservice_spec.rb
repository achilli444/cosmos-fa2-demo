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

# Override at_exit to do nothing for testing
saved_verbose = $VERBOSE; $VERBOSE = nil
def at_exit(*args, &block)
end
$VERBOSE = saved_verbose

module OpenC3
  describe CleanupMicroservice do
    before(:each) do
      mock_redis()
      allow(MicroserviceStatusModel).to receive(:set).with(any_args)
      allow(Metric).to receive(:new).and_return(double("Metric").as_null_object)
      config = { 'cmd' => [], 'topics' => [], 'target_names' => [], 'secrets' => nil, 'plugin' => nil, 'work_dir' => nil }
      allow(MicroserviceModel).to receive(:get).and_return(config)
      @saved = ENV.delete('OPENC3_LOG_MIN_RETAIN_TIME')
      ENV['OPENC3_LOGS_BUCKET'] = 'logs'
      @cleanup = CleanupMicroservice.new('DEFAULT__CLEANUP__INST')
      @logger = @cleanup.instance_variable_get(:@logger)
      @bucket = double("bucket")
    end

    after(:each) do
      ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = @saved if @saved
      @cleanup.shutdown
      thread = @cleanup.instance_variable_get(:@microservice_status_thread)
      thread.join if thread
    end

    describe "cleanup" do
      it "records every deleted log file at info level with the retention used" do
        keys = ['DEFAULT/raw_logs/cmd/INST/20200101/a.bin.gz', 'DEFAULT/raw_logs/cmd/INST/20200101/b.bin.gz']
        allow(BucketUtilities).to receive(:files_between_time).and_return(keys)
        expect(@bucket).to receive(:delete_object).with(bucket: 'logs', key: keys[0])
        expect(@bucket).to receive(:delete_object).with(bucket: 'logs', key: keys[1])
        expect(@logger).to receive(:info).with(/Cleanup deleted logs\/#{Regexp.escape(keys[0])} \(retain_time: 3600s\)/)
        expect(@logger).to receive(:info).with(/Cleanup deleted logs\/#{Regexp.escape(keys[1])} \(retain_time: 3600s\)/)
        expect(@logger).to receive(:info).with(/Cleanup deleted 2 log files under DEFAULT\/raw_logs\/cmd\/INST older than .* \(retain_time: 3600s, first: .*a\.bin\.gz, last: .*b\.bin\.gz\)/)
        allow(@logger).to receive(:info).with(/Shutting down/)
        @cleanup.cleanup([['DEFAULT/raw_logs/cmd/INST', 3600]], @bucket)
      end

      it "raises a retain time below OPENC3_LOG_MIN_RETAIN_TIME to the minimum" do
        ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = '86400'
        now = Time.now
        allow(Time).to receive(:now).and_return(now)
        expect(@logger).to receive(:warn).with(/60s for DEFAULT\/raw_logs\/cmd\/INST is below the minimum 86400s/)
        expect(BucketUtilities).to receive(:files_between_time).with('logs', 'DEFAULT/raw_logs/cmd/INST', nil, now - 86400).and_return([])
        @cleanup.cleanup([['DEFAULT/raw_logs/cmd/INST', 60]], @bucket)
      end

      it "never deletes when the retain time is nil" do
        expect(BucketUtilities).not_to receive(:files_between_time)
        @cleanup.cleanup([['DEFAULT/raw_logs/cmd/INST', nil]], @bucket)
      end
    end
  end
end

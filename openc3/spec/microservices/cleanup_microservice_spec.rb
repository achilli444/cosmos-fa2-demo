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
require 'openc3/microservices/scope_cleanup_microservice'
require 'openc3/models/scope_model'
require 'openc3/models/microservice_model'

# Override at_exit to do nothing for testing
saved_verbose = $VERBOSE; $VERBOSE = nil
def at_exit(*args, &block)
end
$VERBOSE = saved_verbose

module OpenC3
  describe CleanupMicroservice do
    before(:each) do
      mock_redis()
      setup_system()
      allow(MicroserviceStatusModel).to receive(:set).with(any_args)
      # Avoid spawning the Metric update thread (would leak past the test)
      allow(Metric).to receive(:new).and_return(double("Metric").as_null_object)
      @bucket = double("BucketClient")
      allow(Bucket).to receive(:getClient).and_return(@bucket)
      @keys = [
        'DEFAULT/text_logs/openc3_log_messages/20260101/20260101000000000000000__openc3_log_messages.txt',
        'DEFAULT/text_logs/openc3_log_messages/20260101/20260101010000000000000__openc3_log_messages.txt',
      ]
    end

    after(:each) do
      # Shutdown logs at INFO too so don't let it trip the deletion expectations
      allow(@logger).to receive(:info) if @logger
      @cm.shutdown
      @cm.instance_variable_get(:@microservice_status_thread)&.join
    end

    def info_log_lines(stdout)
      stdout.string.lines.map { |line| JSON.parse(line) rescue nil }.compact.select { |msg| msg['level'] == 'INFO' }
    end

    describe "cleanup" do
      before(:each) do
        @cm = CleanupMicroservice.new("DEFAULT__CLEANUP__INST")
        @logger = @cm.instance_variable_get(:@logger)
      end

      it "records every deletion batch at INFO with prefix, retain time, cutoff, count and names" do
        prefix = 'DEFAULT/text_logs/openc3_log_messages'
        allow(BucketUtilities).to receive(:files_between_time).with('logs', prefix, nil, anything).and_return(@keys)
        expect(@bucket).to receive(:delete_object).with(bucket: 'logs', key: @keys[0])
        expect(@bucket).to receive(:delete_object).with(bucket: 'logs', key: @keys[1])

        expect(@logger).to receive(:info).with(
          /Cleanup deleted 2 log files under #{prefix} older than \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \(retain_time 86400s\): #{@keys[0]} \.\. #{@keys[1]}/,
          other: { cleanup: hash_including(prefix: prefix, retain_time: 86400, count: 2, keys: @keys) }
        )
        @cm.cleanup([[prefix, 86400]], @bucket)
      end

      it "writes the deletion record when the log level is INFO (debug suppressed)" do
        prefix = 'DEFAULT/raw_logs/cmd/INST'
        keys = ['DEFAULT/raw_logs/cmd/INST/20260101/20260101000000000000000__INST__ALL__rt__raw.bin']
        allow(BucketUtilities).to receive(:files_between_time).and_return(keys)
        allow(@bucket).to receive(:delete_object)

        capture_io do |stdout|
          @logger.level = Logger::INFO
          @cm.cleanup([[prefix, 3600]], @bucket)
          records = info_log_lines(stdout).select { |msg| msg['message'] =~ /Cleanup deleted/ }
          expect(records.length).to eq(1)
          expect(records[0]['message']).to include("1 log files under #{prefix}")
          expect(records[0]['message']).to include("retain_time 3600s")
          expect(records[0]['cleanup']['keys']).to eq(keys)
          expect(records[0]['cleanup']['count']).to eq(1)
          expect(records[0]['cleanup']['prefix']).to eq(prefix)
        end
      end

      it "emits one record per batch of 1000 objects" do
        prefix = 'DEFAULT/raw_logs/tlm/INST'
        keys = (1..1500).map { |i| "#{prefix}/20260101/#{i}.bin" }
        allow(BucketUtilities).to receive(:files_between_time).and_return(keys)
        allow(@bucket).to receive(:delete_object)

        expect(@logger).to receive(:info).with(/Cleanup deleted 1000 log files under #{prefix}/, other: { cleanup: hash_including(count: 1000, keys: keys[0, 1000]) }).ordered
        expect(@logger).to receive(:info).with(/Cleanup deleted 500 log files under #{prefix}/, other: { cleanup: hash_including(count: 500, keys: keys[1000, 500]) }).ordered
        @cm.cleanup([[prefix, 60]], @bucket)
      end

      it "deletes and logs nothing when no retain time is configured or nothing is expired" do
        allow(BucketUtilities).to receive(:files_between_time).and_return([])
        expect(@bucket).not_to receive(:delete_object)
        expect(@logger).not_to receive(:info).with(/Cleanup deleted/, any_args)
        @cm.cleanup([['DEFAULT/raw_logs/cmd/INST', nil], ['DEFAULT/raw_logs/tlm/INST', 60]], @bucket)
      end
    end

    describe "scope cleanup" do
      it "records audit text log and tool log deletions at INFO" do
        ScopeModel.new(name: 'TEST', text_log_retain_time: 86400, tool_log_retain_time: 7200, cleanup_poll_time: 1).create
        @cm = ScopeCleanupMicroservice.new("TEST__SCOPECLEANUP__TEST")
        scm = @cm
        logger = @logger = @cm.instance_variable_get(:@logger)

        areas, _poll_time = scm.get_areas_and_poll_time()
        expect(areas).to eql([['TEST/text_logs/openc3_log_messages', 86400], ['TEST/tool_logs/sr', 7200]])

        tool_keys = ['TEST/tool_logs/sr/20260101/20260101000000000000000__sr__script.txt']
        allow(BucketUtilities).to receive(:files_between_time).with('logs', 'TEST/text_logs/openc3_log_messages', nil, anything).and_return(@keys)
        allow(BucketUtilities).to receive(:files_between_time).with('logs', 'TEST/tool_logs/sr', nil, anything).and_return(tool_keys)
        allow(@bucket).to receive(:delete_object)

        expect(logger).to receive(:info).with(/Cleanup deleted 2 log files under TEST\/text_logs\/openc3_log_messages .*retain_time 86400s/, other: { cleanup: hash_including(keys: @keys) })
        expect(logger).to receive(:info).with(/Cleanup deleted 1 log files under TEST\/tool_logs\/sr .*retain_time 7200s/, other: { cleanup: hash_including(keys: tool_keys) })
        # Force the poll window to have elapsed so the inherited cleanup runs
        scm.instance_variable_set(:@delta_time, 2.0)
        scm.cleanup(areas, @bucket)
      end
    end
  end
end

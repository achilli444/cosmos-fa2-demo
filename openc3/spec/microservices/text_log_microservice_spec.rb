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
require 'openc3/microservices/text_log_microservice'
require 'openc3/api/metrics_api'

# Override at_exit to do nothing for testing
saved_verbose = $VERBOSE; $VERBOSE = nil
def at_exit(*args, &block)
end
$VERBOSE = saved_verbose

module OpenC3
  describe TextLogMicroservice do
    let(:topic) { '{DEFAULT__openc3_log_messages}' }
    let(:name) { 'DEFAULT__TEXTLOG__openc3_log_messages' }

    before(:each) do
      @metric_sets = []
      metric = double('Metric')
      allow(metric).to receive(:set) { |args| @metric_sets << args }
      allow(metric).to receive(:shutdown)
      allow(Metric).to receive(:new).and_return(metric)
      allow(MicroserviceStatusModel).to receive(:set).with(any_args)
      config = { 'options' => [], 'topics' => [topic], 'target_names' => [], 'secrets' => nil, 'plugin' => nil, 'work_dir' => nil }
      allow(MicroserviceModel).to receive(:get).and_return(config)
      capture_io { @microservice = TextLogMicroservice.new(name) }
    end

    after(:each) do
      capture_io { @microservice.shutdown }
      @microservice.instance_variable_get(:@microservice_status_thread)&.join
    end

    def error_metric_names
      @metric_sets.map { |args| args[:name] }.select { |n| n.include?('error') }.uniq
    end

    describe '#initialize' do
      it 'registers the failure counter under the name the metrics API aggregates' do
        expect(error_metric_names).to eq(['text_log_error_total'])
        expect(Api::SUM_METRICS).to have_key('text_log_error_total')
      end
    end

    describe '#log_data' do
      it 'increments the same failure counter that was initialized' do
        tlw = double('TextLogWriter')
        allow(tlw).to receive(:write).and_raise('bucket unavailable')
        allow(tlw).to receive(:shutdown).and_return([])
        allow(tlw).to receive(:cleanup)
        @microservice.instance_variable_set(:@tlws, { topic => tlw })

        capture_io do
          @microservice.log_data(topic, "#{(Time.now.to_f * 1000).to_i}-0", { 'time' => Time.now.to_nsec_from_epoch }, nil)
        end

        error_sets = @metric_sets.select { |args| args[:name].include?('error') }
        expect(error_sets.map { |args| args[:name] }.uniq).to eq(['text_log_error_total'])
        expect(error_sets.map { |args| args[:value] }).to eq([0, 1])
      end
    end
  end
end

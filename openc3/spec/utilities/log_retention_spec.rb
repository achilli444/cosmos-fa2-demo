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
require 'openc3/utilities/log_retention'

module OpenC3
  describe LogRetention do
    before(:each) { @saved = ENV.delete('OPENC3_LOG_MIN_RETAIN_TIME') }
    after(:each) { ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = @saved if @saved }

    describe "minimum_retain_time" do
      it "is 0 when unset or blank" do
        expect(LogRetention.minimum_retain_time).to eql 0
        ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = ''
        expect(LogRetention.minimum_retain_time).to eql 0
      end

      it "reads seconds from the environment" do
        ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = '604800'
        expect(LogRetention.minimum_retain_time).to eql 604800
      end
    end

    describe "effective_retain_time" do
      it "passes nil through so logs are kept forever" do
        ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = '600'
        expect(LogRetention.effective_retain_time(nil)).to be_nil
      end

      it "leaves retain times at or above the minimum alone" do
        ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = '600'
        expect(LogRetention.effective_retain_time(600)).to eql 600
        expect(LogRetention.effective_retain_time(3600)).to eql 3600
      end

      it "raises shorter retain times to the minimum with a warning" do
        ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = '600'
        logger = double("logger")
        expect(logger).to receive(:warn).with(/60s for DEFAULT\/raw_logs\/cmd\/INST is below the minimum 600s/)
        expect(LogRetention.effective_retain_time(60, prefix: 'DEFAULT/raw_logs/cmd/INST', logger: logger)).to eql 600
      end

      it "does nothing without a configured minimum" do
        expect(LogRetention.effective_retain_time(1)).to eql 1
      end
    end

    describe "retained?" do
      it "is false when no minimum is configured" do
        expect(LogRetention.retained?(Time.now)).to be false
      end

      it "protects objects younger than the minimum and unknown ages" do
        ENV['OPENC3_LOG_MIN_RETAIN_TIME'] = '600'
        now = Time.now
        expect(LogRetention.retained?(now - 10, now: now)).to be true
        expect(LogRetention.retained?(now - 601, now: now)).to be false
        expect(LogRetention.retained?(nil, now: now)).to be true
      end
    end
  end
end

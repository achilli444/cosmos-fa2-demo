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
    let(:now) { Time.utc(2026, 1, 10, 12, 0, 0) }
    let(:day) { 86_400 }

    def log_key(type, start_time, end_time)
      dir = start_time.strftime(BucketUtilities::DIRECTORY_TIMESTAMP_FORMAT)
      "DEFAULT/#{type}/INST/#{dir}/#{start_time.strftime(BucketUtilities::FILE_TIMESTAMP_FORMAT)}__#{end_time.strftime(BucketUtilities::FILE_TIMESTAMP_FORMAT)}__DEFAULT__INST__ALL__rt__raw.bin.gz"
    end

    before(:each) do
      @saved = ENV.fetch(LogRetention::ENV_VAR, nil)
      ENV[LogRetention::ENV_VAR] = (7 * day).to_s
    end

    after(:each) do
      if @saved.nil?
        ENV.delete(LogRetention::ENV_VAR)
      else
        ENV[LogRetention::ENV_VAR] = @saved
      end
    end

    describe "minimum_retain_time" do
      it "returns the configured floor in seconds" do
        expect(LogRetention.minimum_retain_time).to eq(7 * day)
      end

      it "fails closed when unset" do
        ENV.delete(LogRetention::ENV_VAR)
        expect { LogRetention.minimum_retain_time }.to raise_error(LogRetention::RetentionError, /OPENC3_LOG_MIN_RETAIN_TIME must be set/)
      end

      it "fails closed when blank or not a whole number of seconds" do
        ['', ' ', '-1', '7d', 'abc'].each do |value|
          ENV[LogRetention::ENV_VAR] = value
          expect { LogRetention.minimum_retain_time }.to raise_error(LogRetention::RetentionError)
        end
      end
    end

    describe "protected_key?" do
      it "covers raw cmd, raw tlm and decom logs in any scope" do
        expect(LogRetention.protected_key?("DEFAULT/raw_logs/cmd/INST/20260101/file.bin.gz")).to be true
        expect(LogRetention.protected_key?("OTHER/raw_logs/tlm/INST/20260101/file.bin.gz")).to be true
        expect(LogRetention.protected_key?("DEFAULT/decom_logs/tlm/INST/20260101/file.bin.gz")).to be true
        expect(LogRetention.protected_key?("DEFAULT/decom_logs/cmd/INST/20260101/file.bin.gz")).to be true
      end

      it "leaves other logs bucket content alone" do
        expect(LogRetention.protected_key?("DEFAULT/text_logs/openc3_log_messages/20260101/file.txt.gz")).to be false
        expect(LogRetention.protected_key?("DEFAULT/tool_logs/sr/file.txt")).to be false
        expect(LogRetention.protected_key?("raw_logs/cmd/INST/file.bin.gz")).to be false
      end
    end

    describe "check_deletable!" do
      it "allows protected keys whose last record is older than the floor" do
        key = log_key('raw_logs/cmd', now - (10 * day), now - (9 * day))
        expect(LogRetention.check_deletable!([key], now: now)).to eq(now - (7 * day))
      end

      it "refuses protected keys whose last record is inside the floor" do
        old_key = log_key('raw_logs/cmd', now - (10 * day), now - (9 * day))
        young_key = log_key('raw_logs/cmd', now - (8 * day), now - (6 * day))
        expect { LogRetention.check_deletable!([old_key, young_key], now: now) }.to raise_error(LogRetention::RetentionError, /Refusing to delete 1 cmd\/tlm log object.*#{Regexp.escape(young_key)}/)
      end

      it "refuses raw tlm and decom logs inside the floor" do
        expect { LogRetention.check_deletable!([log_key('raw_logs/tlm', now - day, now)], now: now) }.to raise_error(LogRetention::RetentionError)
        expect { LogRetention.check_deletable!([log_key('decom_logs/tlm', now - day, now)], now: now) }.to raise_error(LogRetention::RetentionError)
      end

      it "refuses protected keys whose age cannot be determined" do
        expect { LogRetention.check_deletable!(["DEFAULT/raw_logs/cmd/INST/20260101/notes.txt"], now: now) }.to raise_error(LogRetention::RetentionError)
      end

      it "does not restrict unprotected keys" do
        expect(LogRetention.check_deletable!(["DEFAULT/tool_logs/sr/#{now.to_i}.txt"], now: now)).to eq(now - (7 * day))
      end

      it "fails closed when the floor is unset" do
        ENV.delete(LogRetention::ENV_VAR)
        key = log_key('raw_logs/cmd', now - (400 * day), now - (399 * day))
        expect { LogRetention.check_deletable!([key], now: now) }.to raise_error(LogRetention::RetentionError, /must be set/)
      end
    end

    describe "audit" do
      it "records bucket, prefix, cutoff and keys at info level" do
        logger = double("Logger")
        expect(logger).to receive(:info).with(/Log retention delete: logs\/DEFAULT\/raw_logs\/cmd\/INST 2 object\(s\) older than 2026-01-03T12:00:00Z: a, b/, scope: 'DEFAULT', user: 'admin')
        LogRetention.audit(bucket: 'logs', prefix: 'DEFAULT/raw_logs/cmd/INST', cutoff: now - (7 * day), keys: ['a', 'b'], scope: 'DEFAULT', user: 'admin', logger: logger)
      end
    end
  end
end

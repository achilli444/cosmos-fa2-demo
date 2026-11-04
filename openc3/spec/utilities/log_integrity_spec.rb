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
require 'tempfile'
require 'openc3/utilities/log_integrity'

module OpenC3
  describe LogIntegrity do
    let(:bucket) { 'logs' }
    let(:key) { 'DEFAULT/raw_logs/cmd/INST/20260101/20260101000000000000000__20260101001000000000000.bin.gz' }

    before(:each) do
      @saved_key = ENV.delete('OPENC3_LOG_INTEGRITY_KEY')
      @saved_required = ENV.delete('OPENC3_LOG_INTEGRITY_REQUIRED')
      @file = Tempfile.new(['log', '.bin.gz'])
      @file.binmode
      @file.write('command log contents')
      @file.close
    end

    after(:each) do
      ENV['OPENC3_LOG_INTEGRITY_KEY'] = @saved_key if @saved_key
      ENV['OPENC3_LOG_INTEGRITY_REQUIRED'] = @saved_required if @saved_required
      @file.unlink
    end

    def head_with(metadata)
      OpenStruct.new(metadata: metadata)
    end

    describe "digest_file / metadata_for" do
      it "computes a SHA-256 hex digest by default" do
        expected = OpenSSL::Digest::SHA256.hexdigest('command log contents')
        expect(LogIntegrity.digest_file(@file.path)).to eql expected
        metadata = LogIntegrity.metadata_for(@file.path)
        expect(metadata).to eql({ 'log-digest' => expected, 'log-digest-algorithm' => 'sha256' })
      end

      it "computes an HMAC-SHA256 when OPENC3_LOG_INTEGRITY_KEY is set" do
        ENV['OPENC3_LOG_INTEGRITY_KEY'] = 'managed-key'
        expected = OpenSSL::HMAC.hexdigest('SHA256', 'managed-key', 'command log contents')
        metadata = LogIntegrity.metadata_for(@file.path)
        expect(metadata).to eql({ 'log-digest' => expected, 'log-digest-algorithm' => 'hmac-sha256' })
      end

      it "refuses an HMAC verification without the key" do
        expect { LogIntegrity.digest_file(@file.path, 'hmac-sha256') }.to raise_error(LogIntegrity::IntegrityError, /OPENC3_LOG_INTEGRITY_KEY/)
      end
    end

    describe "index_key" do
      it "places the record under <scope>/log_integrity with a .sha256 suffix" do
        expect(LogIntegrity.index_key(key)).to eql "DEFAULT/log_integrity/raw_logs/cmd/INST/20260101/20260101000000000000000__20260101001000000000000.bin.gz.sha256"
        expect(LogIntegrity.index_key('NOSCOPE/text_logs/openc3_log_messages/20260101/x.txt')).to eql 'NOSCOPE/log_integrity/text_logs/openc3_log_messages/20260101/x.txt.sha256'
      end
    end

    describe "write_index" do
      it "writes a sha256sum style record carrying the same metadata" do
        client = double("client")
        metadata = LogIntegrity.metadata_for(@file.path)
        expect(client).to receive(:put_object) do |args|
          expect(args[:bucket]).to eql bucket
          expect(args[:key]).to eql LogIntegrity.index_key(key)
          expect(args[:body]).to match(/\Asha256  #{metadata['log-digest']}  #{Regexp.escape(key)}  \d{4}-/)
          expect(args[:metadata]).to eql metadata
        end
        LogIntegrity.write_index(client, bucket, key, metadata)
      end
    end

    describe "verify_object" do
      it "passes when the object metadata and index record match the file" do
        metadata = LogIntegrity.metadata_for(@file.path)
        client = double("client")
        allow(client).to receive(:head_object).with(bucket: bucket, key: key).and_return(head_with(metadata))
        allow(client).to receive(:get_object).with(bucket: bucket, key: LogIntegrity.index_key(key)).and_return(OpenStruct.new(body: StringIO.new(LogIntegrity.index_record(key, metadata))))
        expect(LogIntegrity.verify_object(client, bucket, key, @file.path)).to be true
      end

      it "raises when the stored object was modified" do
        metadata = LogIntegrity.metadata_for(@file.path)
        File.binwrite(@file.path, 'tampered log contents')
        client = double("client")
        allow(client).to receive(:head_object).and_return(head_with(metadata))
        allow(client).to receive(:get_object).and_return(nil)
        expect { LogIntegrity.verify_object(client, bucket, key, @file.path) }.to raise_error(LogIntegrity::IntegrityError, /Integrity check failed/)
      end

      it "raises when the index record disagrees with the object metadata" do
        metadata = LogIntegrity.metadata_for(@file.path)
        client = double("client")
        allow(client).to receive(:head_object).and_return(head_with(metadata))
        allow(client).to receive(:get_object).and_return(OpenStruct.new(body: StringIO.new("sha256  #{'0' * 64}  #{key}\n")))
        expect { LogIntegrity.verify_object(client, bucket, key, @file.path) }.to raise_error(LogIntegrity::IntegrityError, /index record/)
      end

      it "warns and returns false for a legacy object without a digest" do
        client = double("client")
        allow(client).to receive(:head_object).and_return(head_with({}))
        expect(Logger).to receive(:warn).with(/No integrity digest stored/)
        expect(LogIntegrity.verify_object(client, bucket, key, @file.path)).to be false
      end

      it "raises for a legacy object when OPENC3_LOG_INTEGRITY_REQUIRED is set" do
        ENV['OPENC3_LOG_INTEGRITY_REQUIRED'] = '1'
        client = double("client")
        allow(client).to receive(:head_object).and_return(head_with({}))
        expect { LogIntegrity.verify_object(client, bucket, key, @file.path) }.to raise_error(LogIntegrity::IntegrityError, /No integrity digest/)
      end
    end
  end
end

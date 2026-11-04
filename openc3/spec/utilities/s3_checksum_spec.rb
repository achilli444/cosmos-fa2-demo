# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software; you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# Regression spec for finding sfind-5a391d352c7f49489972b065e88b9e45 (IR8270-PR.DS-6):
# the local S3 backend must integrity-check downloads. Uses the SDK's built-in
# response stubbing so it runs without a live bucket service.

require 'spec_helper'
require 'base64'
require 'zlib'
require 'digest'
require 'openc3/utilities/s3_autoload'
require 'openc3/utilities/aws_bucket'

module OpenC3
  describe 'S3 checksum configuration' do
    def stubbed_client(body:, crc32: nil, sha256: nil)
      headers = {}
      headers['x-amz-checksum-crc32'] = Base64.strict_encode64([Zlib.crc32(crc32)].pack('N')) if crc32
      headers['x-amz-checksum-sha256'] = Base64.strict_encode64(Digest::SHA256.digest(sha256)) if sha256
      client = Aws::S3::Client.new(stub_responses: true)
      client.stub_responses(:get_object, { status_code: 200, headers: headers, body: body })
      client
    end

    describe 's3_autoload local config' do
      it 'enables response checksum validation for the local backend' do
        expect(Aws.config[:s3][:response_checksum_validation]).to eql 'when_supported'
      end

      it 'keeps request compression disabled for versitygw' do
        expect(Aws.config[:s3][:disable_request_compression]).to be true
      end

      it 'requests checksums on every GET' do
        client = stubbed_client(body: 'hello', crc32: 'hello')
        resp = client.get_object(bucket: 'b', key: 'k')
        expect(resp.context.params[:checksum_mode]).to eql 'ENABLED'
      end

      it 'validates a CRC32 checksum header against the body' do
        client = stubbed_client(body: 'hello', crc32: 'hello')
        resp = client.get_object(bucket: 'b', key: 'k')
        expect(resp.context[:http_checksum][:validated]).to eql 'CRC32'
        expect(resp.body.read).to eql 'hello'
      end

      it 'validates a SHA256 checksum header against the body' do
        client = stubbed_client(body: 'hello', sha256: 'hello')
        resp = client.get_object(bucket: 'b', key: 'k')
        expect(resp.context[:http_checksum][:validated]).to eql 'SHA256'
      end

      it 'raises ChecksumError when the body does not match the checksum header' do
        client = stubbed_client(body: 'hello TAMPERED', crc32: 'hello')
        expect { client.get_object(bucket: 'b', key: 'k') }.to raise_error(Aws::Errors::ChecksumError, /Checksum validation failed/)
      end

      it 'does not validate when response_checksum_validation is when_required (previous behavior)' do
        client = Aws::S3::Client.new(stub_responses: true, response_checksum_validation: 'when_required')
        crc = Base64.strict_encode64([Zlib.crc32('hello')].pack('N'))
        client.stub_responses(:get_object, { status_code: 200, headers: { 'x-amz-checksum-crc32' => crc }, body: 'hello TAMPERED' })
        resp = client.get_object(bucket: 'b', key: 'k')
        expect(resp.context.params[:checksum_mode]).to be_nil
        expect(resp.context[:http_checksum][:validated]).to be_nil
        expect(resp.body.read).to eql 'hello TAMPERED'
      end
    end

    describe 'AwsBucket write checksums' do
      before(:each) do
        @saved = ENV.to_h.slice('OPENC3_CLOUD', 'OPENC3_NO_S3_CHECKSUM')
        allow(Aws::S3::Client).to receive(:new).and_return(Aws::S3::Client.allocate)
      end

      after(:each) do
        ENV.delete('OPENC3_NO_S3_CHECKSUM')
        ENV.delete('OPENC3_CLOUD')
        @saved.each { |k, v| ENV[k] = v }
      end

      it 'requests SHA256 checksums on writes for the local backend' do
        ENV['OPENC3_CLOUD'] = 'local'
        ENV.delete('OPENC3_NO_S3_CHECKSUM')
        expect(AwsBucket.new.instance_variable_get(:@use_checksum)).to be true
      end

      it 'requests SHA256 checksums on writes for AWS' do
        ENV['OPENC3_CLOUD'] = 'aws'
        ENV.delete('OPENC3_NO_S3_CHECKSUM')
        expect(AwsBucket.new.instance_variable_get(:@use_checksum)).to be true
      end

      it 'allows OPENC3_NO_S3_CHECKSUM to disable write checksums for legacy backends' do
        ENV['OPENC3_CLOUD'] = 'local'
        ENV['OPENC3_NO_S3_CHECKSUM'] = '1'
        expect(AwsBucket.new.instance_variable_get(:@use_checksum)).to be false
      end

      it 'treats an empty OPENC3_NO_S3_CHECKSUM as enabled' do
        ENV['OPENC3_CLOUD'] = 'local'
        ENV['OPENC3_NO_S3_CHECKSUM'] = ''
        expect(AwsBucket.new.instance_variable_get(:@use_checksum)).to be true
      end

      it 'passes checksum_algorithm SHA256 to put_object' do
        ENV['OPENC3_CLOUD'] = 'local'
        ENV.delete('OPENC3_NO_S3_CHECKSUM')
        bucket = AwsBucket.new
        client = bucket.instance_variable_get(:@client)
        expect(client).to receive(:put_object).with(hash_including(checksum_algorithm: 'SHA256'))
        bucket.put_object(bucket: 'b', key: 'k', body: 'data')
      end
    end
  end
end

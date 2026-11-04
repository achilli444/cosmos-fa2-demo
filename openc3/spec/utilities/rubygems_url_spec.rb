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
require 'openc3/utilities/rubygems_url'

module OpenC3
  describe RubygemsUrl do
    describe "self.valid?" do
      it "accepts https URLs with a host" do
        expect(RubygemsUrl.valid?('https://rubygems.org')).to be true
        expect(RubygemsUrl.valid?('https://nexus.example.com:8443/repository/rubygems-proxy')).to be true
      end

      it "rejects cleartext http URLs" do
        expect(RubygemsUrl.valid?('http://rubygems.org')).to be false
        expect(RubygemsUrl.valid?('http://10.0.0.5:8081/repository/gems')).to be false
      end

      it "rejects nil, empty, relative and non-http(s) values" do
        expect(RubygemsUrl.valid?(nil)).to be false
        expect(RubygemsUrl.valid?('')).to be false
        expect(RubygemsUrl.valid?('rubygems.org')).to be false
        expect(RubygemsUrl.valid?('https://')).to be false
        expect(RubygemsUrl.valid?('ftp://rubygems.org')).to be false
        expect(RubygemsUrl.valid?('file:///etc/passwd')).to be false
      end

      it "rejects userinfo, whitespace and shell metacharacters" do
        [
          'https://user:pass@rubygems.org',
          'https://rubygems.org; touch /tmp/pwned #',
          'https://rubygems.org$(id)',
          'https://rubygems.org`id`',
          "https://rubygems.org\ntouch /tmp/pwned",
          'https://rubygems.org?a=b',
        ].each do |url|
          expect(RubygemsUrl.valid?(url)).to be(false), "expected #{url.inspect} to be rejected"
        end
      end
    end

    describe "self.validate" do
      it "returns a valid url unchanged" do
        expect(RubygemsUrl.validate('https://nexus.example.com/gems')).to eql 'https://nexus.example.com/gems'
      end

      it "logs and falls back to the default for an invalid url" do
        expect(Logger).to receive(:error).with(/Invalid rubygems_url "http:\/\/rubygems.org"/)
        expect(RubygemsUrl.validate('http://rubygems.org')).to eql RubygemsUrl::DEFAULT_URL
      end
    end
  end
end

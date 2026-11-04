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

require "spec_helper"
require "openc3/utilities/rubygems_url"

module OpenC3
  describe RubygemsUrl do
    describe ".validate" do
      context "with a valid http(s) url" do
        it "returns https urls unchanged" do
          url = "https://rubygems.org"
          expect(RubygemsUrl.validate(url)).to eql url
        end

        it "allows a host with a port" do
          url = "https://localhost:8080"
          expect(RubygemsUrl.validate(url)).to eql url
        end

        it "allows a url with a path" do
          url = "https://gems.example.com/private/gems"
          expect(RubygemsUrl.validate(url)).to eql url
        end

        it "does not log an error" do
          expect(Logger).to_not receive(:error)
          RubygemsUrl.validate("https://rubygems.org")
        end
      end

      context "with an invalid url" do
        it "rejects a value containing shell metacharacters" do
          expect(Logger).to receive(:error)
          payload = "https://rubygems.org ; id > /tmp/PWNED ; #"
          expect(RubygemsUrl.validate(payload)).to eql RubygemsUrl::DEFAULT
        end

        it "rejects plain http unless OPENC3_PACKAGE_SOURCE_ALLOW_HTTP is set" do
          expect(Logger).to receive(:error).with(/plain http is not permitted/)
          expect(RubygemsUrl.validate("http://gems.example.com")).to eql RubygemsUrl::DEFAULT
        end

        it "allows plain http when OPENC3_PACKAGE_SOURCE_ALLOW_HTTP is set, with a warning" do
          allow(ENV).to receive(:[]).and_call_original
          allow(ENV).to receive(:[]).with(PackageSourceUrl::ALLOW_HTTP_ENV).and_return('1')
          expect(Logger).to receive(:warn).with(/plain http/)
          expect(RubygemsUrl.validate("http://gems.example.com")).to eql "http://gems.example.com"
        end

        it "rejects a host that is not on OPENC3_PACKAGE_SOURCE_ALLOWED_HOSTS" do
          allow(ENV).to receive(:[]).and_call_original
          allow(ENV).to receive(:[]).with(PackageSourceUrl::ALLOWED_HOSTS_ENV).and_return('rubygems.org, nexus.example.com')
          expect(Logger).to receive(:error).with(/not listed in OPENC3_PACKAGE_SOURCE_ALLOWED_HOSTS/)
          expect(RubygemsUrl.validate("https://evil.example.com")).to eql RubygemsUrl::DEFAULT
          expect(RubygemsUrl.validate("https://nexus.example.com/repository/gems")).to eql "https://nexus.example.com/repository/gems"
        end

        it "fails closed when the default is not on the allow-list either" do
          allow(ENV).to receive(:[]).and_call_original
          allow(ENV).to receive(:[]).with(PackageSourceUrl::ALLOWED_HOSTS_ENV).and_return('nexus.example.com')
          expect(Logger).to receive(:error)
          expect { RubygemsUrl.validate("https://evil.example.com") }.to raise_error(PackageSourceUrl::Error, /default .* is not permitted/)
        end

        it "rejects a non-http(s) scheme" do
          expect(Logger).to receive(:error)
          expect(RubygemsUrl.validate("ftp://example.com")).to eql RubygemsUrl::DEFAULT
        end

        it "rejects a url with no host" do
          expect(Logger).to receive(:error)
          expect(RubygemsUrl.validate("https:///gems")).to eql RubygemsUrl::DEFAULT
        end

        it "rejects a value that is not a url" do
          expect(Logger).to receive(:error)
          expect(RubygemsUrl.validate("not a url")).to eql RubygemsUrl::DEFAULT
        end

        it "rejects an empty string" do
          expect(Logger).to receive(:error)
          expect(RubygemsUrl.validate("")).to eql RubygemsUrl::DEFAULT
        end
      end
    end

    describe "DEFAULT" do
      it "is the public rubygems source" do
        expect(RubygemsUrl::DEFAULT).to eql "https://rubygems.org"
      end
    end
  end
end

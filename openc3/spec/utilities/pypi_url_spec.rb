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
require "openc3/utilities/pypi_url"

module OpenC3
  describe PypiUrl do
    describe ".validate" do
      context "with a valid http(s) url" do
        it "returns https urls unchanged" do
          url = "https://pypi.org/simple"
          expect(PypiUrl.validate(url)).to eql url
        end

        it "allows a host with a port" do
          url = "https://localhost:8080/simple"
          expect(PypiUrl.validate(url)).to eql url
        end

        it "rejects plain http unless OPENC3_PACKAGE_SOURCE_ALLOW_HTTP is set" do
          expect(Logger).to receive(:error).with(/plain http is not permitted/)
          expect(PypiUrl.validate("http://pypi.example.com/simple")).to eql PypiUrl::DEFAULT
        end

        it "allows plain http when OPENC3_PACKAGE_SOURCE_ALLOW_HTTP is set, with a warning" do
          allow(ENV).to receive(:[]).and_call_original
          allow(ENV).to receive(:[]).with(PackageSourceUrl::ALLOW_HTTP_ENV).and_return('1')
          expect(Logger).to receive(:warn).with(/plain http/)
          expect(PypiUrl.validate("http://pypi.example.com/simple")).to eql "http://pypi.example.com/simple"
        end

        it "rejects a host that is not on OPENC3_PACKAGE_SOURCE_ALLOWED_HOSTS" do
          allow(ENV).to receive(:[]).and_call_original
          allow(ENV).to receive(:[]).with(PackageSourceUrl::ALLOWED_HOSTS_ENV).and_return('pypi.org,nexus.example.com:8443')
          expect(Logger).to receive(:error).with(/not listed in OPENC3_PACKAGE_SOURCE_ALLOWED_HOSTS/)
          expect(PypiUrl.validate("https://evil.example.com/simple")).to eql PypiUrl::DEFAULT
          expect(PypiUrl.validate("https://nexus.example.com:8443/simple")).to eql "https://nexus.example.com:8443/simple"
        end

        it "does not log an error" do
          expect(Logger).to_not receive(:error)
          PypiUrl.validate("https://pypi.org/simple")
        end
      end

      context "with an invalid url" do
        # Shell metacharacters that previously enabled command injection
        it "rejects a value containing shell metacharacters" do
          expect(Logger).to receive(:error)
          payload = "https://pypi.org ; id > /tmp/PWNED ; #"
          expect(PypiUrl.validate(payload)).to eql PypiUrl::DEFAULT
        end

        it "rejects a non-http(s) scheme" do
          expect(Logger).to receive(:error)
          expect(PypiUrl.validate("ftp://example.com/simple")).to eql PypiUrl::DEFAULT
        end

        it "rejects a url with no host" do
          expect(Logger).to receive(:error)
          expect(PypiUrl.validate("https:///simple")).to eql PypiUrl::DEFAULT
        end

        it "rejects a value that is not a url" do
          expect(Logger).to receive(:error)
          expect(PypiUrl.validate("not a url")).to eql PypiUrl::DEFAULT
        end

        it "rejects an empty string" do
          expect(Logger).to receive(:error)
          expect(PypiUrl.validate("")).to eql PypiUrl::DEFAULT
        end
      end
    end

    describe "DEFAULT" do
      it "is the public pypi simple index" do
        expect(PypiUrl::DEFAULT).to eql "https://pypi.org/simple"
      end
    end
  end
end

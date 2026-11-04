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
require "openc3/utilities/package_source_url"

module OpenC3
  describe PackageSourceUrl do
    describe ".check!" do
      it "accepts an https url with a host" do
        expect(PackageSourceUrl.check!("https://nexus.example.com:8443/repository/pypi", env: {})).to eql "https://nexus.example.com:8443/repository/pypi"
      end

      it "rejects plain http by default" do
        expect { PackageSourceUrl.check!("http://pypi.example.com", env: {}) }
          .to raise_error(PackageSourceUrl::Error, /plain http is not permitted/)
      end

      it "accepts plain http only with OPENC3_PACKAGE_SOURCE_ALLOW_HTTP, logging a warning" do
        expect(Logger).to receive(:warn).with(/plain http/)
        env = { PackageSourceUrl::ALLOW_HTTP_ENV => '1' }
        expect(PackageSourceUrl.check!("http://pypi.example.com", env: env)).to eql "http://pypi.example.com"
        %w(0 false no off).each do |value|
          expect { PackageSourceUrl.check!("http://pypi.example.com", env: { PackageSourceUrl::ALLOW_HTTP_ENV => value }) }
            .to raise_error(PackageSourceUrl::Error, /plain http/)
        end
      end

      it "enforces the host allow-list, matching host or host:port case-insensitively" do
        env = { PackageSourceUrl::ALLOWED_HOSTS_ENV => ' Rubygems.org, nexus.example.com:8443 ' }
        expect(PackageSourceUrl.check!("https://rubygems.org", env: env)).to eql "https://rubygems.org"
        expect(PackageSourceUrl.check!("https://NEXUS.example.com:8443/simple", env: env)).to eql "https://NEXUS.example.com:8443/simple"
        expect { PackageSourceUrl.check!("https://nexus.example.com/simple", env: env) }
          .to raise_error(PackageSourceUrl::Error, /host 'nexus.example.com' is not listed/)
        expect { PackageSourceUrl.check!("https://rubygems.org.evil.example.com", env: env) }
          .to raise_error(PackageSourceUrl::Error, /not listed/)
      end

      it "rejects non-http schemes, missing hosts and non-urls" do
        ["ftp://example.com", "https:///gems", "not a url", "", nil,
         "https://rubygems.org ; id > /tmp/PWNED ; #"].each do |value|
          expect { PackageSourceUrl.check!(value, env: {}) }.to raise_error(PackageSourceUrl::Error)
        end
      end
    end

    describe ".validate" do
      it "falls back to the default when it is permitted" do
        expect(Logger).to receive(:error).with(/Invalid pypi_url 'http:\/\/x.example.com'/)
        expect(PackageSourceUrl.validate("http://x.example.com", default: "https://pypi.org", label: 'pypi_url', env: {})).to eql "https://pypi.org"
      end

      it "raises when the default is not permitted either" do
        allow(Logger).to receive(:error)
        env = { PackageSourceUrl::ALLOWED_HOSTS_ENV => 'nexus.example.com' }
        expect { PackageSourceUrl.validate("https://x.example.com", default: "https://pypi.org", label: 'pypi_url', env: env) }
          .to raise_error(PackageSourceUrl::Error, /default https:\/\/pypi.org is not permitted/)
      end
    end
  end
end

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
require "openc3/utilities/package_integrity"

module OpenC3
  describe PackageIntegrity do
    before(:each) do
      @temp_dir = Dir.mktmpdir
      @pkg = File.join(@temp_dir, "demo-1.0.0.gem")
      File.write(@pkg, "package bytes")
      @digest = Digest::SHA256.hexdigest("package bytes")
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with('OPENC3_PACKAGE_ALLOWLIST', nil).and_return(nil)
      allow(ENV).to receive(:fetch).with('OPENC3_GEM_SECURITY_POLICY', 'MediumSecurity').and_return('MediumSecurity')
      allow(ENV).to receive(:fetch).with('OPENC3_GEM_TRUST_DIR', nil).and_return(nil)
    end

    after(:each) do
      FileUtils.remove_entry_secure(@temp_dir, true)
    end

    describe ".gem_security_policy" do
      it "defaults to MediumSecurity" do
        expect(PackageIntegrity.gem_security_policy).to eql Gem::Security::MediumSecurity
      end

      it "treats an empty value as the default" do
        allow(ENV).to receive(:fetch).with('OPENC3_GEM_SECURITY_POLICY', 'MediumSecurity').and_return('  ')
        expect(PackageIntegrity.gem_security_policy).to eql Gem::Security::MediumSecurity
      end

      it "resolves every RubyGems policy by name" do
        PackageIntegrity::GEM_SECURITY_POLICIES.each do |name, policy|
          allow(ENV).to receive(:fetch).with('OPENC3_GEM_SECURITY_POLICY', 'MediumSecurity').and_return(name)
          expect(PackageIntegrity.gem_security_policy).to eql policy
        end
      end

      it "raises on an unknown policy name" do
        allow(ENV).to receive(:fetch).with('OPENC3_GEM_SECURITY_POLICY', 'MediumSecurity').and_return('Medium')
        expect { PackageIntegrity.gem_security_policy }.to raise_error(PackageIntegrityError, /Unknown OPENC3_GEM_SECURITY_POLICY 'Medium'/)
      end

      it "points RubyGems at OPENC3_GEM_TRUST_DIR" do
        original = Gem::Security.trust_dir
        begin
          trust = File.join(@temp_dir, "trust")
          allow(ENV).to receive(:fetch).with('OPENC3_GEM_TRUST_DIR', nil).and_return(trust)
          PackageIntegrity.gem_security_policy
          expect(Gem::Security.trust_dir.dir).to eql trust
        ensure
          Gem::Security.instance_variable_set(:@trust_dir, original)
        end
      end
    end

    describe ".verify!" do
      it "returns and logs the SHA-256 digest when no allow-list is configured" do
        expect(Logger).to receive(:info).with("Verified package demo-1.0.0.gem sha256=#{@digest}", scope: "DEFAULT")
        expect(PackageIntegrity.verify!(@pkg, scope: "DEFAULT")).to eql @digest
      end

      context "with OPENC3_PACKAGE_ALLOWLIST" do
        before(:each) do
          @allowlist = File.join(@temp_dir, "allowlist.txt")
          allow(ENV).to receive(:fetch).with('OPENC3_PACKAGE_ALLOWLIST', nil).and_return(@allowlist)
        end

        it "accepts a listed digest in sha256sum format, ignoring comments and case" do
          File.write(@allowlist, "# approved packages\n#{'0' * 64}  other.gem\n#{@digest.upcase}  demo-1.0.0.gem # ok\n")
          expect(Logger).to receive(:info).with(/sha256=#{@digest} \(allow-listed\)/, scope: nil)
          expect(PackageIntegrity.verify!(@pkg)).to eql @digest
        end

        it "accepts a bare digest line" do
          File.write(@allowlist, "#{@digest}\n")
          allow(Logger).to receive(:info)
          expect(PackageIntegrity.verify!(@pkg)).to eql @digest
        end

        it "rejects an unlisted digest" do
          File.write(@allowlist, "#{'0' * 64}  other.gem\n")
          expect(Logger).to receive(:error).with(/demo-1.0.0.gem rejected: sha256=#{@digest} is not in OPENC3_PACKAGE_ALLOWLIST/, scope: nil)
          expect { PackageIntegrity.verify!(@pkg) }.to raise_error(PackageIntegrityError, /not in OPENC3_PACKAGE_ALLOWLIST/)
        end

        it "rejects everything when the allow-list is empty" do
          File.write(@allowlist, "# nothing approved yet\n")
          allow(Logger).to receive(:error)
          expect { PackageIntegrity.verify!(@pkg) }.to raise_error(PackageIntegrityError)
        end

        it "fails closed when the allow-list can't be read" do
          expect { PackageIntegrity.verify!(@pkg) }.to raise_error(PackageIntegrityError, /Cannot read OPENC3_PACKAGE_ALLOWLIST/)
        end

        it "fails closed on a malformed digest" do
          File.write(@allowlist, "deadbeef  demo-1.0.0.gem\n")
          expect { PackageIntegrity.verify!(@pkg) }.to raise_error(PackageIntegrityError, /Malformed SHA-256 digest 'deadbeef'/)
        end
      end
    end
  end
end

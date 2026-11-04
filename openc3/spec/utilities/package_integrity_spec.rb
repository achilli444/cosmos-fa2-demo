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
require 'openc3/utilities/package_integrity'

module OpenC3
  describe PackageIntegrity do
    before(:each) do
      @saved_env = ENV.to_h.slice('OPENC3_PACKAGE_ALLOWLIST', 'OPENC3_PACKAGE_INTEGRITY')
      ENV.delete('OPENC3_PACKAGE_INTEGRITY')
      @package = Tempfile.new(['plugin', '.gem'])
      @package.write("not really a gem")
      @package.close
      @digest = Digest::SHA256.file(@package.path).hexdigest
      @allowlist = Tempfile.new(['allowlist', '.sha256'])
      allow(Logger).to receive(:info)
      allow(Logger).to receive(:warn)
      allow(Logger).to receive(:error)
    end

    after(:each) do
      @package.unlink
      @allowlist.unlink
      ['OPENC3_PACKAGE_ALLOWLIST', 'OPENC3_PACKAGE_INTEGRITY'].each do |key|
        @saved_env.key?(key) ? ENV[key] = @saved_env[key] : ENV.delete(key)
      end
    end

    def write_allowlist(contents)
      @allowlist.rewind
      @allowlist.truncate(0)
      @allowlist.write(contents)
      @allowlist.flush
      ENV['OPENC3_PACKAGE_ALLOWLIST'] = @allowlist.path
    end

    describe "self.mode" do
      it "defaults to enforce" do
        expect(PackageIntegrity.mode).to eql 'enforce'
        expect(PackageIntegrity.enforcing?).to be true
      end

      it "treats unknown values as enforce" do
        ENV['OPENC3_PACKAGE_INTEGRITY'] = 'off'
        expect(PackageIntegrity.mode).to eql 'enforce'
        ENV['OPENC3_PACKAGE_INTEGRITY'] = 'disabled'
        expect(PackageIntegrity.mode).to eql 'enforce'
      end

      it "accepts audit" do
        ENV['OPENC3_PACKAGE_INTEGRITY'] = ' Audit '
        expect(PackageIntegrity.mode).to eql 'audit'
        expect(PackageIntegrity.enforcing?).to be false
      end
    end

    describe "self.allowed_digests" do
      it "parses sha256sum format, bare digests and comments" do
        other = 'a' * 64
        write_allowlist("# approved plugins\n#{@digest}  openc3-cosmos-demo-1.0.0.gem\n#{other.upcase}\n\n")
        expect(PackageIntegrity.allowed_digests).to eql Set.new([@digest, other])
      end

      it "ignores malformed entries and logs them" do
        write_allowlist("#{@digest}  ok.gem\nnot-a-digest  bad.gem\n#{'b' * 63}\n")
        expect(Logger).to receive(:error).with(/malformed package allow-list entry/).twice
        expect(PackageIntegrity.allowed_digests).to eql Set.new([@digest])
      end

      it "reads every file in OPENC3_PACKAGE_ALLOWLIST and logs missing ones" do
        write_allowlist("#{@digest}\n")
        ENV['OPENC3_PACKAGE_ALLOWLIST'] = "#{@allowlist.path}#{File::PATH_SEPARATOR}/nonexistent/allowlist.sha256"
        expect(Logger).to receive(:error).with(%r{/nonexistent/allowlist.sha256 does not exist})
        expect(PackageIntegrity.allowed_digests).to eql Set.new([@digest])
      end

      it "is empty when no allow-list is provisioned" do
        ENV.delete('OPENC3_PACKAGE_ALLOWLIST')
        allow(File).to receive(:file?).and_call_original
        allow(File).to receive(:file?).with(PackageIntegrity::DEFAULT_ALLOWLIST_PATH).and_return(false)
        expect(PackageIntegrity.allowlist_paths).to eql []
        expect(PackageIntegrity.allowed_digests).to be_empty
      end

      it "uses the default allow-list path when present" do
        ENV.delete('OPENC3_PACKAGE_ALLOWLIST')
        allow(File).to receive(:file?).and_call_original
        allow(File).to receive(:file?).with(PackageIntegrity::DEFAULT_ALLOWLIST_PATH).and_return(true)
        expect(PackageIntegrity.allowlist_paths).to eql [PackageIntegrity::DEFAULT_ALLOWLIST_PATH]
      end
    end

    describe "self.verify!" do
      it "returns the digest when the package is allow-listed" do
        write_allowlist("#{@digest}  #{File.basename(@package.path)}\n")
        expect(Logger).to receive(:info).with(/Package integrity verified/)
        expect(PackageIntegrity.verify!(@package.path)).to eql @digest
      end

      it "rejects a package that is not allow-listed" do
        write_allowlist("#{'c' * 64}  something-else.gem\n")
        expect(Logger).to receive(:error).with(/not in the package allow-list/)
        expect { PackageIntegrity.verify!(@package.path) }.to raise_error(PackageIntegrityError, /sha256=#{@digest} is not in the package allow-list/)
      end

      it "rejects every package when no allow-list is provisioned" do
        ENV.delete('OPENC3_PACKAGE_ALLOWLIST')
        allow(File).to receive(:file?).and_call_original
        allow(File).to receive(:file?).with(PackageIntegrity::DEFAULT_ALLOWLIST_PATH).and_return(false)
        expect { PackageIntegrity.verify!(@package.path) }.to raise_error(PackageIntegrityError, /not in the package allow-list/)
      end

      it "rejects a package whose contents changed after it was allow-listed" do
        write_allowlist("#{@digest}\n")
        File.open(@package.path, 'a') { |f| f.write("tampered") }
        expect { PackageIntegrity.verify!(@package.path) }.to raise_error(PackageIntegrityError)
      end

      it "raises when the file does not exist" do
        write_allowlist("#{@digest}\n")
        expect { PackageIntegrity.verify!('/nonexistent/plugin.gem') }.to raise_error(PackageIntegrityError, /does not exist/)
      end

      it "only warns in audit mode" do
        ENV['OPENC3_PACKAGE_INTEGRITY'] = 'audit'
        write_allowlist("#{'c' * 64}\n")
        expect(Logger).to receive(:warn).with(/Installing anyway because OPENC3_PACKAGE_INTEGRITY=audit/)
        expect(PackageIntegrity.verify!(@package.path)).to eql @digest
      end
    end
  end
end

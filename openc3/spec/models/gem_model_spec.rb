# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'tempfile'
require 'ostruct'
require 'openc3/models/plugin_model'
require 'openc3/models/gem_model'
require 'openc3/utilities/aws_bucket'
require 'fileutils'

module OpenC3
  describe GemModel do
    before(:each) do
      mock_redis()
      @orig_gem_home = ENV.fetch('GEM_HOME', nil)
      @temp_dir = Dir.mktmpdir
      ENV['GEM_HOME'] = @temp_dir
      @scope = "DEFAULT"
      @gem_list = ['openc3-test1.gem', 'openc3-test2.gem']
      FileUtils.mkdir_p("#{ENV.fetch('GEM_HOME')}/cache")
      @gem_list.each do |gem|
        FileUtils.mkdir_p("#{ENV.fetch('GEM_HOME')}/gems/#{File.basename(gem, '.gem')}")
        FileUtils.touch("#{ENV.fetch('GEM_HOME')}/cache/#{gem}")
      end
    end

    after(:each) do
      FileUtils.remove_entry_secure(@temp_dir, true)
      @temp_dir = nil
      ENV['GEM_HOME'] = @orig_gem_home
    end

    describe "self.names" do
      it "returns a list of gem names" do
        expect(GemModel.names).to eql ["openc3-test1.gem", "openc3-test2.gem"]
      end
    end

    describe "self.get" do
      it "get the gem on the local filesystem" do
        path = GemModel.get('openc3-test1.gem')
        expect(path).to eql "#{ENV.fetch('GEM_HOME')}/cache/openc3-test1.gem"
      end
    end

    describe "self.put" do
      it "raises if the gem doesn't exist" do
        expect { GemModel.put('another.gem', scope: 'DEFAULT') }.to raise_error(/does not exist/)
      end

      it "rejects a gem that is not on OPENC3_PACKAGE_ALLOWLIST before caching it" do
        allowlist = File.join(@temp_dir, "allowlist.txt")
        File.write(allowlist, "#{'b' * 64}\n")
        allow(ENV).to receive(:fetch).and_call_original
        allow(ENV).to receive(:fetch).with('OPENC3_PACKAGE_ALLOWLIST', nil).and_return(allowlist)
        allow(Logger).to receive(:error)
        tf = Tempfile.new("openc3-test3.gem")
        tf.write("not approved")
        tf.close
        expect { GemModel.put(tf.path, scope: 'DEFAULT') }.to raise_error(PackageIntegrityError, /not in OPENC3_PACKAGE_ALLOWLIST/)
        expect(Dir.exist?("#{ENV.fetch('GEM_HOME')}/cosmoscache")).to be false
        tf.unlink
      end

      it "puts the gem to the gem server" do
        pm = class_double("OpenC3::ProcessManager").as_stubbed_const(:transfer_nested_constants => true)
        result = double("fakepm")
        expect(result).to receive(:name).and_return("1234__56")
        expect(pm).to receive_message_chain(:instance, :spawn).and_return(result)
        tf = Tempfile.new("openc3-test3.gem")
        tf.close
        GemModel.put(tf.path, scope: 'DEFAULT')
        tf.unlink
      end
    end

    describe "self.install" do
      context "integrity" do
        before(:each) do
          # A real (empty-spec) gem so Gem.install is reached
          @gem_file = File.join(@temp_dir, "openc3-real-1.0.0.gem")
          Dir.mktmpdir do |dir|
            spec = Gem::Specification.new do |s|
              s.name = 'openc3-real'
              s.version = '1.0.0'
              s.summary = 'test'
              s.authors = ['test']
            end
            Dir.chdir(dir) { Gem::Package.build(spec, true) } # skip_validation silences gemspec warnings
            FileUtils.mv(File.join(dir, 'openc3-real-1.0.0.gem'), @gem_file)
          end
          allow(GemModel).to receive(:get_setting).with('rubygems_url', scope: 'DEFAULT').and_return(nil)
        end

        it "installs with the MediumSecurity policy by default and logs the digest" do
          allow(Logger).to receive(:info)
          expect(Gem).to receive(:install).with(@gem_file, "> 0.pre", hash_including(security_policy: Gem::Security::MediumSecurity, domain: :local))
          GemModel.install(@gem_file, scope: 'DEFAULT')
          digest = Digest::SHA256.file(@gem_file).hexdigest
          expect(Logger).to have_received(:info).with("Verified package openc3-real-1.0.0.gem sha256=#{digest}", scope: 'DEFAULT')
        end

        it "applies the policy to the remote retry as well" do
          expect(Gem).to receive(:install).with(@gem_file, "> 0.pre", hash_including(security_policy: Gem::Security::MediumSecurity, domain: :local)).and_raise(Gem::Exception, "local miss")
          expect(Gem).to receive(:install).with(@gem_file, "> 0.pre", hash_including(security_policy: Gem::Security::MediumSecurity, domain: :both))
          GemModel.install(@gem_file, scope: 'DEFAULT')
        end

        it "honors OPENC3_GEM_SECURITY_POLICY=HighSecurity and rejects an unsigned gem" do
          allow(ENV).to receive(:fetch).and_call_original
          allow(ENV).to receive(:fetch).with('OPENC3_GEM_SECURITY_POLICY', 'MediumSecurity').and_return('HighSecurity')
          allow(Logger).to receive(:error)
          # Both the local and remote attempts run the real installer, which refuses unsigned gems under HighSecurity
          expect { GemModel.install(@gem_file, scope: 'DEFAULT') }.to raise_error(Gem::Security::Exception, /unsigned gems are not allowed/)
        end

        it "fails closed on an unknown OPENC3_GEM_SECURITY_POLICY" do
          allow(ENV).to receive(:fetch).and_call_original
          allow(ENV).to receive(:fetch).with('OPENC3_GEM_SECURITY_POLICY', 'MediumSecurity').and_return('Whatever')
          allow(Logger).to receive(:error)
          expect(Gem).to_not receive(:install)
          expect { GemModel.install(@gem_file, scope: 'DEFAULT') }.to raise_error(PackageIntegrityError, /Unknown OPENC3_GEM_SECURITY_POLICY 'Whatever'/)
        end

        it "rejects a gem whose digest is not on OPENC3_PACKAGE_ALLOWLIST" do
          allowlist = File.join(@temp_dir, "allowlist.txt")
          File.write(allowlist, "# approved\n#{'a' * 64}  something-else.gem\n")
          allow(ENV).to receive(:fetch).and_call_original
          allow(ENV).to receive(:fetch).with('OPENC3_PACKAGE_ALLOWLIST', nil).and_return(allowlist)
          allow(Logger).to receive(:error)
          expect(Gem).to_not receive(:install)
          expect { GemModel.install(@gem_file, scope: 'DEFAULT') }.to raise_error(PackageIntegrityError, /not in OPENC3_PACKAGE_ALLOWLIST/)
          expect(Logger).to have_received(:error).with(/openc3-real-1.0.0.gem rejected: sha256=/, scope: 'DEFAULT')
        end

        it "installs a gem whose digest is on OPENC3_PACKAGE_ALLOWLIST" do
          digest = Digest::SHA256.file(@gem_file).hexdigest
          allowlist = File.join(@temp_dir, "allowlist.txt")
          File.write(allowlist, "#{digest.upcase}  openc3-real-1.0.0.gem\n")
          allow(ENV).to receive(:fetch).and_call_original
          allow(ENV).to receive(:fetch).with('OPENC3_PACKAGE_ALLOWLIST', nil).and_return(allowlist)
          allow(Logger).to receive(:info)
          expect(Gem).to receive(:install).with(@gem_file, "> 0.pre", hash_including(security_policy: Gem::Security::MediumSecurity))
          GemModel.install(@gem_file, scope: 'DEFAULT')
          expect(Logger).to have_received(:info).with("Verified package openc3-real-1.0.0.gem sha256=#{digest} (allow-listed)", scope: 'DEFAULT')
        end
      end

      it "existing gemfile and handles missing" do
        expect { GemModel.install("openc3-test1.gem", scope: 'DEFAULT') }.to \
          raise_error(Gem::Package::FormatError, /package metadata is missing/)
        expect { GemModel.install("openc3-test3.gem", scope: 'DEFAULT') }.to \
          raise_error(RuntimeError, /Gem 'openc3-test3.gem' not found/)
      end

      context "rubygems_url resolution" do
        # The gem itself is invalid so install always raises, but Gem.sources is
        # set before that happens which is what we're verifying
        def install_test_gem
          expect { GemModel.install("openc3-test1.gem", scope: 'DEFAULT') }.to \
            raise_error(Gem::Package::FormatError)
        end

        it "uses the rubygems_url setting" do
          allow(GemModel).to receive(:get_setting).with('rubygems_url', scope: 'DEFAULT')
            .and_return("https://gems.example.com")
          expect(Gem).to receive(:sources=).with(["https://gems.example.com"])
          install_test_gem()
        end

        it "replaces an invalid rubygems_url setting with the default" do
          allow(GemModel).to receive(:get_setting).with('rubygems_url', scope: 'DEFAULT')
            .and_return("https://rubygems.org ; id > /tmp/PWNED ; #")
          allow(Logger).to receive(:error)
          expect(Gem).to receive(:sources=).with([RubygemsUrl::DEFAULT])
          install_test_gem()
          expect(Logger).to have_received(:error).with(/Invalid rubygems_url/)
        end

        it "doesn't set sources when the setting is nil" do
          allow(GemModel).to receive(:get_setting).with('rubygems_url', scope: 'DEFAULT').and_return(nil)
          expect(Gem).to_not receive(:sources=)
          install_test_gem()
        end

        it "falls back to ENV RUBYGEMS_URL when get_setting raises" do
          allow(GemModel).to receive(:get_setting).with('rubygems_url', scope: 'DEFAULT')
            .and_raise(RuntimeError.new("no redis"))
          allow(ENV).to receive(:fetch).and_call_original
          allow(ENV).to receive(:fetch).with('RUBYGEMS_URL', RubygemsUrl::DEFAULT)
            .and_return("https://env.gems.example.com")
          expect(Gem).to receive(:sources=).with(["https://env.gems.example.com"])
          install_test_gem()
        end

        it "falls back to the default when get_setting raises and ENV is unset" do
          allow(GemModel).to receive(:get_setting).with('rubygems_url', scope: 'DEFAULT')
            .and_raise(RuntimeError.new("no redis"))
          allow(ENV).to receive(:fetch).and_call_original
          allow(ENV).to receive(:fetch).with('RUBYGEMS_URL', RubygemsUrl::DEFAULT).and_return(RubygemsUrl::DEFAULT)
          expect(Gem).to receive(:sources=).with([RubygemsUrl::DEFAULT])
          install_test_gem()
        end
      end
    end

    describe "self.destroy" do
      it "removes the gem from the gem server" do
        uninstaller = instance_double("Gem::Uninstaller").as_null_object
        expect(Gem::Uninstaller).to receive(:new).and_return(uninstaller)
        expect(uninstaller).to receive(:uninstall)
        GemModel.destroy("openc3-test1.gem")
      end
    end

    describe "self.destroy_all_other_versions" do
      it "removes the gem from the gem server" do
        uninstaller = instance_double("Gem::Uninstaller").as_null_object
        expect(Gem::Uninstaller).to receive(:new).and_return(uninstaller)
        expect(uninstaller).to receive(:uninstall)
        GemModel.destroy_all_other_versions("openc3-test1.gem")
      end
    end
  end
end

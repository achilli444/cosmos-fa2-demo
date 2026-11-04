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
require 'openc3/utilities/package_integrity'
require 'openc3/utilities/rubygems_url'
require 'digest'
require 'openc3/utilities/aws_bucket'
require 'fileutils'

module OpenC3
  describe GemModel do
    before(:each) do
      mock_redis()
      @orig_gem_home = ENV['GEM_HOME']
      @temp_dir = Dir.mktmpdir
      ENV['GEM_HOME'] = @temp_dir
      @scope = "DEFAULT"
      @gem_list = ['openc3-test1.gem', 'openc3-test2.gem']
      FileUtils.mkdir_p("#{ENV['GEM_HOME']}/cache")
      @gem_list.each do |gem|
        FileUtils.mkdir_p("#{ENV['GEM_HOME']}/gems/#{File.basename(gem, '.gem')}")
        FileUtils.touch("#{ENV['GEM_HOME']}/cache/#{gem}")
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
        expect(path).to eql "#{ENV['GEM_HOME']}/cache/openc3-test1.gem"
      end
    end

    describe "self.put" do
      it "raises if the gem doesn't exist" do
        expect { GemModel.put('another.gem', scope: 'DEFAULT') }.to raise_error(/does not exist/)
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
      before(:each) do
        @saved_env = ENV.to_h.slice('OPENC3_PACKAGE_ALLOWLIST', 'OPENC3_PACKAGE_INTEGRITY', 'OPENC3_GEM_SECURITY_POLICY', 'OPENC3_GEM_REMOTE_DEPENDENCIES', 'RUBYGEMS_URL')
        ENV.delete('OPENC3_PACKAGE_INTEGRITY')
        ENV.delete('OPENC3_GEM_SECURITY_POLICY')
        ENV.delete('OPENC3_GEM_REMOTE_DEPENDENCIES')
        ENV.delete('RUBYGEMS_URL')
        @allowlist = Tempfile.new(['allowlist', '.sha256'])
        @allowlist.puts Digest::SHA256.file("#{ENV['GEM_HOME']}/cache/openc3-test1.gem").hexdigest
        @allowlist.close
        ENV['OPENC3_PACKAGE_ALLOWLIST'] = @allowlist.path
        @saved_sources = Gem.sources.to_a
        allow(GemModel).to receive(:get_setting).and_raise("no redis")
        allow(Logger).to receive(:info)
        allow(Logger).to receive(:warn)
        allow(Logger).to receive(:error)
      end

      after(:each) do
        Gem.sources = @saved_sources
        @allowlist.unlink
        @saved_env.each_key { |key| @saved_env.key?(key) ? ENV[key] = @saved_env[key] : ENV.delete(key) }
        ['OPENC3_PACKAGE_ALLOWLIST', 'OPENC3_PACKAGE_INTEGRITY', 'OPENC3_GEM_SECURITY_POLICY', 'OPENC3_GEM_REMOTE_DEPENDENCIES', 'RUBYGEMS_URL'].each do |key|
          ENV.delete(key) unless @saved_env.key?(key)
        end
      end

      it "existing gemfile and handles missing" do
        expect { GemModel.install("openc3-test1.gem", scope: 'DEFAULT') }.to \
          raise_error(Gem::Package::FormatError, /package metadata is missing/)
        expect { GemModel.install("openc3-test3.gem", scope: 'DEFAULT') }.to \
          raise_error(RuntimeError, /Gem openc3-test3.gem not found/)
      end

      it "rejects a gem that is not allow-listed before anything is installed" do
        File.write("#{ENV['GEM_HOME']}/cache/openc3-test2.gem", "different contents")
        expect(Gem).not_to receive(:install)
        expect { GemModel.install("openc3-test2.gem", scope: 'DEFAULT') }.to \
          raise_error(PackageIntegrityError, /openc3-test2.gem sha256=[0-9a-f]{64} is not in the package allow-list/)
      end

      it "rejects every gem when no allow-list is provisioned" do
        ENV.delete('OPENC3_PACKAGE_ALLOWLIST')
        allow(File).to receive(:file?).and_call_original
        allow(File).to receive(:file?).with(PackageIntegrity::DEFAULT_ALLOWLIST_PATH).and_return(false)
        expect(Gem).not_to receive(:install)
        expect { GemModel.install("openc3-test1.gem", scope: 'DEFAULT') }.to raise_error(PackageIntegrityError)
      end

      it "installs an allow-listed gem from local sources only without a trust policy by default" do
        expect(Gem).to receive(:install).once do |path, requirement, **options|
          expect(path).to end_with('openc3-test1.gem')
          expect(options[:domain]).to eql :local
          expect(options).not_to have_key(:security_policy)
        end
        GemModel.install("openc3-test1.gem", scope: 'DEFAULT')
      end

      it "does not fall back to remote dependency resolution unless OPENC3_GEM_REMOTE_DEPENDENCIES=1" do
        expect(Gem).to receive(:install).once.with(anything, anything, hash_including(domain: :local)).and_raise(Gem::InstallError, "needs dep")
        expect { GemModel.install("openc3-test1.gem", scope: 'DEFAULT') }.to raise_error(Gem::InstallError, /needs dep/)
      end

      it "falls back to remote dependency resolution when opted in" do
        ENV['OPENC3_GEM_REMOTE_DEPENDENCIES'] = '1'
        expect(Gem).to receive(:install).with(anything, anything, hash_including(domain: :local)).ordered.and_raise(Gem::InstallError, "needs dep")
        expect(Gem).to receive(:install).with(anything, anything, hash_including(domain: :both)).ordered
        GemModel.install("openc3-test1.gem", scope: 'DEFAULT')
      end

      it "applies the OPENC3_GEM_SECURITY_POLICY trust policy" do
        ENV['OPENC3_GEM_SECURITY_POLICY'] = 'HighSecurity'
        expect(Gem).to receive(:install).with(anything, anything, hash_including(security_policy: Gem::Security::HighSecurity, domain: :local))
        GemModel.install("openc3-test1.gem", scope: 'DEFAULT')
      end

      it "rejects an unknown OPENC3_GEM_SECURITY_POLICY" do
        ENV['OPENC3_GEM_SECURITY_POLICY'] = 'NoSecurity'
        expect(Gem).not_to receive(:install)
        expect { GemModel.install("openc3-test1.gem", scope: 'DEFAULT') }.to raise_error(ArgumentError, /Unknown OPENC3_GEM_SECURITY_POLICY/)
      end

      it "uses a valid https rubygems_url setting as the gem source" do
        allow(GemModel).to receive(:get_setting).with('rubygems_url', scope: 'DEFAULT').and_return('https://nexus.example.com/gems')
        expect(Gem).to receive(:install)
        GemModel.install("openc3-test1.gem", scope: 'DEFAULT')
        expect(Gem.sources.to_a).to eql ['https://nexus.example.com/gems']
      end

      ['http://nexus.example.com/gems', 'https://user:pass@rubygems.org', 'https://rubygems.org$(id)', 'file:///etc/passwd'].each do |url|
        it "falls back to #{RubygemsUrl::DEFAULT_URL} for invalid rubygems_url #{url.inspect}" do
          allow(GemModel).to receive(:get_setting).with('rubygems_url', scope: 'DEFAULT').and_return(url)
          expect(Logger).to receive(:error).with(/Invalid rubygems_url/)
          expect(Gem).to receive(:install)
          GemModel.install("openc3-test1.gem", scope: 'DEFAULT')
          expect(Gem.sources.to_a).to eql [RubygemsUrl::DEFAULT_URL]
        end
      end

      it "rejects a cleartext RUBYGEMS_URL environment fallback" do
        ENV['RUBYGEMS_URL'] = 'http://nexus.example.com/gems'
        expect(Logger).to receive(:error).with(/Invalid rubygems_url/)
        expect(Gem).to receive(:install)
        GemModel.install("openc3-test1.gem", scope: 'DEFAULT')
        expect(Gem.sources.to_a).to eql [RubygemsUrl::DEFAULT_URL]
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

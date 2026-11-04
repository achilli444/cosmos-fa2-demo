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
require 'digest'
require 'openc3/models/python_package_model'
require 'openc3/utilities/package_integrity'

module OpenC3
  describe PythonPackageModel do
    describe "self.install" do
      before(:each) do
        mock_redis()
        @saved_env = ENV.to_h.slice('OPENC3_PACKAGE_ALLOWLIST', 'OPENC3_PACKAGE_INTEGRITY', 'PIP_ENABLE_TRUSTED_HOST', 'PYPI_URL')
        ENV.delete('OPENC3_PACKAGE_INTEGRITY')
        ENV.delete('PIP_ENABLE_TRUSTED_HOST')
        ENV.delete('PYPI_URL')
        @package = Tempfile.new(['openc3_pkg-1.0.0-py3-none-any', '.whl'])
        @package.write("wheel contents")
        @package.close
        @allowlist = Tempfile.new(['allowlist', '.sha256'])
        @allowlist.puts Digest::SHA256.file(@package.path).hexdigest
        @allowlist.close
        ENV['OPENC3_PACKAGE_ALLOWLIST'] = @allowlist.path
        allow(PythonPackageModel).to receive(:get_setting).and_return(nil)
        allow(Logger).to receive(:info)
        allow(Logger).to receive(:warn)
        allow(Logger).to receive(:error)
        @pm = class_double("OpenC3::ProcessManager").as_stubbed_const(:transfer_nested_constants => true)
        @result = double("process", name: "1234__56")
      end

      after(:each) do
        @package.unlink
        @allowlist.unlink
        ['OPENC3_PACKAGE_ALLOWLIST', 'OPENC3_PACKAGE_INTEGRITY', 'PIP_ENABLE_TRUSTED_HOST', 'PYPI_URL'].each do |key|
          @saved_env.key?(key) ? ENV[key] = @saved_env[key] : ENV.delete(key)
        end
      end

      def expect_spawn
        expect(@pm).to receive_message_chain(:instance, :spawn) do |argv, *_rest|
          @argv = argv
          @result
        end
      end

      it "installs an allow-listed package with --no-deps and never --trusted-host" do
        ENV['PIP_ENABLE_TRUSTED_HOST'] = '1'
        expect_spawn
        expect(PythonPackageModel.install(@package.path, scope: 'DEFAULT')).to eql "1234__56"
        expect(@argv).to eql ['/openc3/bin/pipinstall', '-i', 'https://pypi.org/simple', '--no-deps', @package.path]
        expect(@argv).not_to include('--trusted-host')
      end

      it "rejects a package that is not allow-listed before spawning pip" do
        File.open(@package.path, 'a') { |f| f.write("tampered") }
        expect(@pm).not_to receive(:instance)
        expect { PythonPackageModel.install(@package.path, scope: 'DEFAULT') }.to raise_error(PackageIntegrityError, /not in the package allow-list/)
      end

      it "uses a valid https pypi_url setting" do
        allow(PythonPackageModel).to receive(:get_setting).with('pypi_url', scope: 'DEFAULT').and_return('https://mirror.example.com')
        expect_spawn
        PythonPackageModel.install(@package.path, scope: 'DEFAULT')
        expect(@argv[1..2]).to eql ['-i', 'https://mirror.example.com/simple']
      end

      ['http://mirror.example.com', 'https://user:pass@pypi.org', 'https://pypi.org; touch /tmp/pwned #', 'file:///etc/passwd'].each do |url|
        it "rejects invalid pypi_url #{url.inspect} and never spawns a subprocess" do
          allow(PythonPackageModel).to receive(:get_setting).with('pypi_url', scope: 'DEFAULT').and_return(url)
          expect(@pm).not_to receive(:instance)
          expect(Logger).to receive(:error).with(/Invalid pypi_url/)
          expect { PythonPackageModel.install(@package.path, scope: 'DEFAULT') }.to raise_error(/Invalid pypi_url/)
        end
      end

      it "rejects a cleartext PYPI_URL environment fallback" do
        ENV['PYPI_URL'] = 'http://10.0.0.5:3141/root/pypi'
        expect(@pm).not_to receive(:instance)
        expect { PythonPackageModel.install(@package.path, scope: 'DEFAULT') }.to raise_error(/Invalid pypi_url/)
      end
    end
  end
end

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
require 'openc3/utilities/default_secrets'

module OpenC3
  describe DefaultSecrets do
    let(:secure_env) do
      {
        'SECRET_KEY_BASE' => 'a' * 128,
        'OPENC3_REDIS_PASSWORD' => 'r' * 32,
        'OPENC3_SR_REDIS_PASSWORD' => 's' * 32,
        'OPENC3_BUCKET_PASSWORD' => 'b' * 32,
        'OPENC3_SR_BUCKET_PASSWORD' => 'c' * 32,
        'OPENC3_TSDB_PASSWORD' => 't' * 32,
        'OPENC3_SERVICE_PASSWORD' => 'v' * 32,
      }
    end
    let(:shipped_env) do
      DefaultSecrets::DEFAULT_PASSWORDS.merge('SECRET_KEY_BASE' => DefaultSecrets::SHIPPED_SECRET_KEY_BASES.first)
    end

    describe "self.default_passwords_in_use" do
      it "returns nothing for unique passwords" do
        expect(DefaultSecrets.default_passwords_in_use(secure_env)).to eql []
      end

      it "returns every variable still set to a shipped placeholder" do
        env = secure_env.merge('OPENC3_SERVICE_PASSWORD' => 'openc3service', 'OPENC3_REDIS_PASSWORD' => 'openc3password')
        expect(DefaultSecrets.default_passwords_in_use(env)).to contain_exactly('OPENC3_SERVICE_PASSWORD', 'OPENC3_REDIS_PASSWORD')
      end

      it "ignores unset variables" do
        expect(DefaultSecrets.default_passwords_in_use({})).to eql []
      end
    end

    describe "self.secret_key_base_problem" do
      it "accepts a long unique key" do
        expect(DefaultSecrets.secret_key_base_problem(secure_env)).to be_nil
      end

      it "rejects a blank key" do
        expect(DefaultSecrets.secret_key_base_problem({})).to match(/not set/)
        expect(DefaultSecrets.secret_key_base_problem('SECRET_KEY_BASE' => '  ')).to match(/not set/)
      end

      it "rejects the key that was committed to the repository" do
        expect(DefaultSecrets.secret_key_base_problem(shipped_env)).to match(/public COSMOS repository/)
      end

      it "rejects short keys" do
        expect(DefaultSecrets.secret_key_base_problem('SECRET_KEY_BASE' => 'abc')).to match(/too short/)
      end
    end

    describe "self.allowed?" do
      it "recognizes truthy opt-in values" do
        ['1', 'true', 'YES', 'on'].each do |value|
          expect(DefaultSecrets.allowed?('OPENC3_ALLOW_DEFAULT_PASSWORDS' => value)).to be true
        end
      end

      it "is false when unset or falsy" do
        expect(DefaultSecrets.allowed?({})).to be false
        expect(DefaultSecrets.allowed?('OPENC3_ALLOW_DEFAULT_PASSWORDS' => '0')).to be false
        expect(DefaultSecrets.allowed?('OPENC3_ALLOW_DEFAULT_PASSWORDS' => 'false')).to be false
      end
    end

    describe "self.check!" do
      let(:logger) { double('logger', warn: nil, error: nil) }

      it "passes silently for a secure environment" do
        expect(DefaultSecrets.check!(service: 'test', env: secure_env, logger: logger)).to be true
        expect(logger).not_to have_received(:warn)
        expect(logger).not_to have_received(:error)
      end

      it "raises when shipped secrets are in use and no opt-in is set" do
        expect { DefaultSecrets.check!(service: 'test', env: shipped_env, logger: logger) }.to raise_error(DefaultSecrets::Error, /refusing to start/)
        expect(logger).to have_received(:error).with(/OPENC3_SERVICE_PASSWORD/)
      end

      it "raises when only SECRET_KEY_BASE is missing" do
        env = secure_env.reject { |key, _| key == 'SECRET_KEY_BASE' }
        expect { DefaultSecrets.check!(service: 'test', env: env, logger: logger) }.to raise_error(DefaultSecrets::Error, /SECRET_KEY_BASE is not set/)
      end

      it "only warns when OPENC3_ALLOW_DEFAULT_PASSWORDS is set" do
        env = shipped_env.merge('OPENC3_ALLOW_DEFAULT_PASSWORDS' => '1')
        expect(DefaultSecrets.check!(service: 'test', env: env, logger: logger)).to be false
        expect(logger).to have_received(:warn).with(/insecure shipped secrets/)
      end

      it "writes to stderr without a logger" do
        expect { DefaultSecrets.check!(service: 'test', env: shipped_env) }.to raise_error(DefaultSecrets::Error).and output(/ERROR: test refusing/).to_stderr
      end
    end
  end
end

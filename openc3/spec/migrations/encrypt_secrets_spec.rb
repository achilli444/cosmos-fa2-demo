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
ENV['OPENC3_NO_MIGRATE'] = 'true'
require 'openc3/migrations/20261104000000_encrypt_secrets'
require 'openc3/utilities/redis_secrets'

module OpenC3
  describe EncryptSecrets do
    before(:each) do
      @redis = mock_redis()
      ScopeModel.new(name: 'DEFAULT').create
      @redis.hset('DEFAULT__openc3__secrets', 'LEGACY', JSON.generate({ 'name' => 'LEGACY', 'value' => 'oldvalue' }))
      @redis.hset(OfflineAccessModel::PRIMARY_KEY, 'alice',
                  JSON.generate({ 'name' => 'alice', 'updated_at' => 1, 'offline_access_token' => 'old-refresh', 'scope' => 'DEFAULT' }))
      @redis.hset(OfflineAccessModel::PRIMARY_KEY, 'bob',
                  JSON.generate({ 'name' => 'bob', 'updated_at' => 1, 'offline_access_token' => nil, 'scope' => 'DEFAULT' }))
    end

    it "re-encrypts legacy plaintext secrets and offline access tokens" do
      expect { EncryptSecrets.run }.to output(/Encrypted secret LEGACY/).to_stdout
      raw = @redis.hget('DEFAULT__openc3__secrets', 'LEGACY')
      expect(raw).not_to include('oldvalue')
      expect(JSON.parse(raw)['value']).to start_with('enc:v1:')
      expect(RedisSecrets.new.get('LEGACY', scope: 'DEFAULT')).to eq('oldvalue')

      raw = @redis.hget(OfflineAccessModel::PRIMARY_KEY, 'alice')
      expect(raw).not_to include('old-refresh')
      expect(OfflineAccessModel.get_model(name: 'alice', scope: 'DEFAULT').offline_access_token).to eq('old-refresh')
      expect(OfflineAccessModel.get_model(name: 'bob', scope: 'DEFAULT').offline_access_token).to be_nil
    end

    it "is idempotent" do
      EncryptSecrets.run
      first = @redis.hget('DEFAULT__openc3__secrets', 'LEGACY')
      expect { EncryptSecrets.run }.not_to output(/Encrypted/).to_stdout
      expect(@redis.hget('DEFAULT__openc3__secrets', 'LEGACY')).to eq(first)
    end

    it "refuses to run without a key" do
      saved = ENV['OPENC3_SECRET_ENCRYPTION_KEY']
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = nil
      expect { EncryptSecrets.run }.to raise_error(SecretEncryption::KeyMissingError)
      expect(@redis.hget('DEFAULT__openc3__secrets', 'LEGACY')).to include('oldvalue')
    ensure
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = saved
    end
  end
end

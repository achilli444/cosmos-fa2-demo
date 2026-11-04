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
require 'openc3/utilities/redis_secrets'

module OpenC3
  describe RedisSecrets do
    before(:each) do
      @redis = mock_redis()
      @secrets = RedisSecrets.new
    end

    it "never writes the plaintext value to Redis" do
      @secrets.set('PASSWORD', 'hunter2', scope: 'DEFAULT')
      raw = @redis.hget('DEFAULT__openc3__secrets', 'PASSWORD')
      expect(raw).not_to include('hunter2')
      expect(JSON.parse(raw)['value']).to start_with('enc:v1:')
      expect(@secrets.get('PASSWORD', scope: 'DEFAULT')).to eq('hunter2')
      expect(@secrets.keys(scope: 'DEFAULT')).to eq(['PASSWORD'])
    end

    it "still reads secrets stored as plaintext before encryption existed" do
      @redis.hset('DEFAULT__openc3__secrets', 'LEGACY', JSON.generate({ 'name' => 'LEGACY', 'value' => 'oldvalue' }))
      expect(@secrets.get('LEGACY', scope: 'DEFAULT')).to eq('oldvalue')
    end

    it "refuses to store a secret without an encryption key" do
      saved = ENV['OPENC3_SECRET_ENCRYPTION_KEY']
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = nil
      expect { @secrets.set('PASSWORD', 'hunter2', scope: 'DEFAULT') }.to raise_error(SecretEncryption::KeyMissingError)
      expect(@redis.hget('DEFAULT__openc3__secrets', 'PASSWORD')).to be_nil
    ensure
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = saved
    end

    it "deletes secrets" do
      @secrets.set('PASSWORD', 'hunter2', scope: 'DEFAULT')
      @secrets.delete('PASSWORD', scope: 'DEFAULT')
      expect(@secrets.get('PASSWORD', scope: 'DEFAULT')).to be_nil
    end
  end
end

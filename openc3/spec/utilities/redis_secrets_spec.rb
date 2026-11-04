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
require 'openc3/utilities/store'

module OpenC3
  describe RedisSecrets do
    before(:each) do
      mock_redis()
      @saved_key = ENV['OPENC3_SECRETS_KEY']
      ENV['OPENC3_SECRETS_KEY'] = 'ab' * 32
      @secrets = RedisSecrets.new
    end

    after(:each) do
      ENV['OPENC3_SECRETS_KEY'] = @saved_key
    end

    def raw_value(name, scope: 'DEFAULT')
      JSON.parse(Store.hget("#{scope}__openc3__secrets", name))['value']
    end

    it "stores only ciphertext in Redis and returns the plaintext from get" do
      @secrets.set('MQTT_PASSWORD', 'hunter2', scope: 'DEFAULT')
      raw = raw_value('MQTT_PASSWORD')
      expect(raw).to be_a(Hash)
      expect(raw['alg']).to eql 'aes-256-gcm'
      expect(Store.hget('DEFAULT__openc3__secrets', 'MQTT_PASSWORD')).not_to include('hunter2')
      expect(@secrets.get('MQTT_PASSWORD', scope: 'DEFAULT')).to eql 'hunter2'
      expect(@secrets.keys(scope: 'DEFAULT')).to eql ['MQTT_PASSWORD']
    end

    it "stringifies non-string values before encrypting" do
      @secrets.set('PORT', 8883, scope: 'DEFAULT')
      expect(@secrets.get('PORT', scope: 'DEFAULT')).to eql '8883'
    end

    it "returns nil for a missing secret" do
      expect(@secrets.get('NOPE', scope: 'DEFAULT')).to be_nil
    end

    it "deletes secrets" do
      @secrets.set('MQTT_PASSWORD', 'hunter2', scope: 'DEFAULT')
      @secrets.delete('MQTT_PASSWORD', scope: 'DEFAULT')
      expect(@secrets.get('MQTT_PASSWORD', scope: 'DEFAULT')).to be_nil
      expect(@secrets.keys(scope: 'DEFAULT')).to eql []
    end

    it "still reads a legacy plaintext secret and warns" do
      Store.hset('DEFAULT__openc3__secrets', 'OLD', JSON.generate({ 'name' => 'OLD', 'value' => 'legacy' }))
      expect(Logger).to receive(:warn).with(/Secret 'OLD' is stored unencrypted/, scope: 'DEFAULT')
      expect(@secrets.get('OLD', scope: 'DEFAULT')).to eql 'legacy'
    end

    it "encrypts a legacy plaintext secret when it is set again" do
      Store.hset('DEFAULT__openc3__secrets', 'OLD', JSON.generate({ 'name' => 'OLD', 'value' => 'legacy' }))
      @secrets.set('OLD', 'legacy', scope: 'DEFAULT')
      expect(raw_value('OLD')).to be_a(Hash)
      allow(Logger).to receive(:warn)
      expect(@secrets.get('OLD', scope: 'DEFAULT')).to eql 'legacy'
    end

    it "refuses to store a secret when no key is configured" do
      ENV.delete('OPENC3_SECRETS_KEY')
      expect { @secrets.set('MQTT_PASSWORD', 'hunter2', scope: 'DEFAULT') }.to raise_error(SecretCipher::KeyError)
      expect(Store.hget('DEFAULT__openc3__secrets', 'MQTT_PASSWORD')).to be_nil
    end

    it "rejects a ciphertext copied to another secret name" do
      @secrets.set('A', 'hunter2', scope: 'DEFAULT')
      Store.hset('DEFAULT__openc3__secrets', 'B', JSON.generate({ 'name' => 'B', 'value' => raw_value('A') }))
      expect { @secrets.get('B', scope: 'DEFAULT') }.to raise_error(SecretCipher::DecryptError)
    end

    it "keeps scopes separate" do
      @secrets.set('PW', 'one', scope: 'DEFAULT')
      @secrets.set('PW', 'two', scope: 'OTHER')
      expect(@secrets.get('PW', scope: 'DEFAULT')).to eql 'one'
      expect(@secrets.get('PW', scope: 'OTHER')).to eql 'two'
    end
  end
end

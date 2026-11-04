# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/models/offline_access_model'

module OpenC3
  describe OfflineAccessModel, type: :model do
    TOKEN = 'eyJhbGciOiJIUzI1NiJ9.offline-refresh-token'

    before(:each) do
      mock_redis()
      @saved_key = ENV['OPENC3_SECRETS_KEY']
      @saved_key_file = ENV['OPENC3_SECRETS_KEY_FILE']
      ENV['OPENC3_SECRETS_KEY'] = 'ab' * 32
      ENV['OPENC3_SECRETS_KEY_FILE'] = nil
    end

    after(:each) do
      ENV['OPENC3_SECRETS_KEY'] = @saved_key
      ENV['OPENC3_SECRETS_KEY_FILE'] = @saved_key_file
    end

    describe "process_status" do
      it "creates new" do
        model = OfflineAccessModel.new(name: 'ps', scope: 'DEFAULT')
        expect(model).to be_a(OfflineAccessModel)
      end

      it "self.get" do
        name = OfflineAccessModel.get(name: 'ps', scope: 'DEFAULT')
        expect(name).to be_nil # eq('ps')
      end

      it "self.all" do
        all = OfflineAccessModel.all(scope: 'DEFAULT')
        expect(all[0]).to be_nil # eq('ps')
      end

      it "self.names" do
        names = OfflineAccessModel.names(scope: 'DEFAULT')
        expect(names[0]).to be_nil # eq('ps')
      end

      it "as_json" do
        model = OfflineAccessModel.new(name: 'ps', scope: 'DEFAULT')
        expect(model.as_json()['name']).to eq('ps')
        expect(model.as_json()['offline_access_token']).to be_nil
      end
    end

    describe "offline_access_token at rest" do
      it "is encrypted in as_json and in Redis" do
        model = OfflineAccessModel.new(name: 'alice', offline_access_token: TOKEN, scope: 'DEFAULT')
        expect(model.offline_access_token).to eq(TOKEN)
        json = model.as_json()
        expect(SecretCipher.encrypted?(json['offline_access_token'])).to be true
        expect(json.to_json).not_to include(TOKEN)

        model.create
        stored = OfflineAccessModel.get(name: 'alice', scope: 'DEFAULT')
        expect(SecretCipher.encrypted?(stored['offline_access_token'])).to be true
        raw = Store.hget(OfflineAccessModel::PRIMARY_KEY, 'alice')
        expect(raw).not_to include(TOKEN)
      end

      it "is decrypted when the model is read back" do
        OfflineAccessModel.new(name: 'alice', offline_access_token: TOKEN, scope: 'DEFAULT').create
        model = OfflineAccessModel.get_model(name: 'alice', scope: 'DEFAULT')
        expect(model.offline_access_token).to eq(TOKEN)
        all = OfflineAccessModel.get_all_models(scope: 'DEFAULT')
        expect(all['alice'].offline_access_token).to eq(TOKEN)
      end

      it "re-encrypts on update" do
        model = OfflineAccessModel.new(name: 'alice', offline_access_token: TOKEN, scope: 'DEFAULT')
        model.create
        model.offline_access_token = 'rotated-token'
        model.update
        expect(Store.hget(OfflineAccessModel::PRIMARY_KEY, 'alice')).not_to include('rotated-token')
        expect(OfflineAccessModel.get_model(name: 'alice', scope: 'DEFAULT').offline_access_token).to eq('rotated-token')
      end

      it "clears the token with nil" do
        model = OfflineAccessModel.new(name: 'alice', offline_access_token: TOKEN, scope: 'DEFAULT')
        model.create
        model.offline_access_token = nil
        model.update
        expect(OfflineAccessModel.get_model(name: 'alice', scope: 'DEFAULT').offline_access_token).to be_nil
      end

      it "reads tokens stored in plaintext before encryption was introduced" do
        Store.hset(OfflineAccessModel::PRIMARY_KEY, 'legacy', JSON.generate({ 'name' => 'legacy', 'offline_access_token' => TOKEN, 'scope' => 'DEFAULT' }))
        model = OfflineAccessModel.get_model(name: 'legacy', scope: 'DEFAULT')
        expect(model.offline_access_token).to eq(TOKEN)
        model.update
        expect(Store.hget(OfflineAccessModel::PRIMARY_KEY, 'legacy')).not_to include(TOKEN)
      end

      it "binds the token to the user name" do
        OfflineAccessModel.new(name: 'alice', offline_access_token: TOKEN, scope: 'DEFAULT').create
        stored = OfflineAccessModel.get(name: 'alice', scope: 'DEFAULT')
        Store.hset(OfflineAccessModel::PRIMARY_KEY, 'mallory', JSON.generate(stored.merge('name' => 'mallory')))
        expect(Logger).to receive(:error).with(/Unable to decrypt offline access token for mallory/)
        expect(OfflineAccessModel.get_model(name: 'mallory', scope: 'DEFAULT').offline_access_token).to be_nil
      end

      it "treats tokens encrypted under a different key as absent" do
        OfflineAccessModel.new(name: 'alice', offline_access_token: TOKEN, scope: 'DEFAULT').create
        ENV['OPENC3_SECRETS_KEY'] = 'cd' * 32
        expect(Logger).to receive(:error).with(/Unable to decrypt offline access token for alice/)
        expect(OfflineAccessModel.get_model(name: 'alice', scope: 'DEFAULT').offline_access_token).to be_nil
      end

      it "refuses to store a token without OPENC3_SECRETS_KEY" do
        ENV['OPENC3_SECRETS_KEY'] = nil
        model = OfflineAccessModel.new(name: 'alice', offline_access_token: TOKEN, scope: 'DEFAULT')
        expect { model.create }.to raise_error(SecretCipher::KeyError, /OPENC3_SECRETS_KEY/)
        expect(Store.hget(OfflineAccessModel::PRIMARY_KEY, 'alice')).to be_nil
      end

      it "decrypts a token encrypted by the Python SecretCipher" do
        python_envelope = ENV['PYTHON_ENCRYPTED_FIXTURE']
        skip 'PYTHON_ENCRYPTED_FIXTURE not set' unless python_envelope
        Store.hset(OfflineAccessModel::PRIMARY_KEY, 'alice', JSON.generate({ 'name' => 'alice', 'offline_access_token' => JSON.parse(python_envelope), 'scope' => 'DEFAULT' }))
        expect(OfflineAccessModel.get_model(name: 'alice', scope: 'DEFAULT').offline_access_token).to eq(TOKEN)
      end
    end
  end
end

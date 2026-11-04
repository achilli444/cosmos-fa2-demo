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
require 'openc3/models/offline_access_model'

module OpenC3
  describe OfflineAccessModel, type: :model do
    before(:each) do
      mock_redis()
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

      it "encrypts the offline access token at rest and decrypts it on load" do
        model = OfflineAccessModel.new(name: 'alice', offline_access_token: 'refresh-token', scope: 'DEFAULT')
        model.create
        raw = OpenC3::Store.hget(OfflineAccessModel::PRIMARY_KEY, 'alice')
        expect(raw).not_to include('refresh-token')
        expect(JSON.parse(raw)['offline_access_token']).to start_with('enc:v1:')
        loaded = OfflineAccessModel.get_model(name: 'alice', scope: 'DEFAULT')
        expect(loaded.offline_access_token).to eq('refresh-token')
        loaded.offline_access_token = nil
        loaded.update
        expect(OfflineAccessModel.get_model(name: 'alice', scope: 'DEFAULT').offline_access_token).to be_nil
      end
    end
  end
end

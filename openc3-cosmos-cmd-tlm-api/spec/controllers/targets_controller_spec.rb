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

require 'rails_helper'
require 'openc3/models/model'
require 'openc3/models/target_model'

RSpec.describe TargetsController, :type => :controller do
  before(:each) do
    mock_redis()
    ENV.delete('OPENC3_LOCAL_MODE')
  end

  describe "all_modified" do
    it "lists all modified targets for a scope" do
      allow(OpenC3::TargetModel).to receive(:all_modified).and_return(["INST"])
      get :all_modified, params: { scope: 'DEFAULT' }
      expect(response).to have_http_status(:ok)
      ret = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(ret).to eql(['INST'])
    end

    it "rejects a bad scope param" do
      get :all_modified, params: { scope: '../DEFAULT' }
      expect(response).to have_http_status(:bad_request)
      ret = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(ret['message']).to eql('Invalid scope: ../DEFAULT')
    end
  end

  describe "delete_modified" do
    it "writes a user-attributed audit record on success" do
      allow(OpenC3::TargetModel).to receive(:delete_modified).with('INST', scope: 'DEFAULT')
      allow(OpenC3::Logger).to receive(:info)
      expect(OpenC3::Logger).to receive(:info).with(
        /\AAudit: anonymous POST \S+ targets#delete_modified id=INST scope=DEFAULT => success \(200\)\z/,
        hash_including(scope: 'DEFAULT', user: 'anonymous')
      )
      post :delete_modified, params: { scope: 'DEFAULT', id: 'INST' }
      expect(response).to have_http_status(:ok)
    end
  end
end

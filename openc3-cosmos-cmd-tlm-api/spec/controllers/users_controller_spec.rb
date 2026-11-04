# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

require "rails_helper"

RSpec.describe UsersController, type: :controller do
  describe "UsersController" do
    it "GET active" do
      get :active
      expect(response).to have_http_status(:ok)
    end

    it "Logout terminates only the caller's own session token" do
      request.headers['HTTP_AUTHORIZATION'] = 'ses_mytoken'
      expect(OpenC3::AuthModel).to receive(:terminate).with('ses_mytoken')
      put :logout, params: {user: "user", scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
    end

    it "Logout writes an audit record without the token" do
      mock_redis()
      request.headers['HTTP_AUTHORIZATION'] = 'ses_mytoken'
      request.remote_addr = '1.2.3.4'
      records = []
      allow(OpenC3::Logger).to receive(:info).and_wrap_original do |original, *args, **kwargs|
        records << [args[0], kwargs] if kwargs[:type] == OpenC3::Logger::AUDIT
        original.call(*args, **kwargs)
      end
      put :logout, params: {user: "user", scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      logout = records.find { |_message, kwargs| kwargs[:other][:event] == 'logout' }
      expect(logout).not_to be_nil
      expect(logout[1][:user]).to eql 'anonymous'
      expect(logout[1][:other]).to include(client_id: '1.2.3.4', endpoint: 'users#logout', outcome: 'success')
      expect(records.to_s).not_to include('ses_mytoken')
    end
  end
end

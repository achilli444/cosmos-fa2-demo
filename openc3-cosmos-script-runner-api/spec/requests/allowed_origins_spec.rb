# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software: you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'rails_helper'

# spec_helper sets OPENC3_ALLOWED_ORIGINS=http://localhost:2900 before Rails boots
RSpec.describe 'allowed origins and host authorization', type: :request do
  let(:allowed_origin) { 'http://localhost:2900' }

  describe 'ActionDispatch::HostAuthorization (config.hosts)' do
    it 'serves requests addressed to the configured COSMOS URL' do
      get '/script-api/ping', headers: { 'Host' => 'localhost:2900' }
      expect(response).to have_http_status(:ok)
      expect(response.body).to eq('OK')
    end

    it 'serves requests addressed to the service hostname used by Traefik' do
      get '/script-api/ping', headers: { 'Host' => 'openc3-cosmos-script-runner-api:2902' }
      expect(response).to have_http_status(:ok)
    end

    it 'rejects requests addressed to an unknown host' do
      get '/script-api/ping', headers: { 'Host' => 'attacker.example' }
      expect(response).to have_http_status(:forbidden)
    end

    it 'rejects requests with an unknown X-Forwarded-Host' do
      get '/script-api/ping', headers: { 'Host' => 'localhost:2900', 'X-Forwarded-Host' => 'attacker.example' }
      expect(response).to have_http_status(:forbidden)
    end
  end

  describe 'Rack::Cors' do
    let(:preflight_headers) do
      { 'Host' => 'localhost:2900', 'Access-Control-Request-Method' => 'POST', 'Access-Control-Request-Headers' => 'Authorization' }
    end

    it 'answers preflight requests from an allowed origin' do
      options '/script-api/scripts/test.rb/run', headers: preflight_headers.merge('Origin' => allowed_origin)
      expect(response.headers['Access-Control-Allow-Origin']).to eq(allowed_origin)
      expect(response.headers['Access-Control-Allow-Methods']).to include('POST')
    end

    it 'does not grant cross-origin access to other origins' do
      options '/script-api/scripts/test.rb/run', headers: preflight_headers.merge('Origin' => 'https://attacker.example')
      expect(response.headers['Access-Control-Allow-Origin']).to be_nil
    end

    it 'never reflects a wildcard origin' do
      get '/script-api/ping', headers: { 'Host' => 'localhost:2900', 'Origin' => 'https://attacker.example' }
      expect(response.headers['Access-Control-Allow-Origin']).to be_nil
    end
  end

  describe 'Action Cable origin check' do
    it 'keeps request forgery protection enabled' do
      expect(Rails.application.config.action_cable.disable_request_forgery_protection).to be_falsey
    end

    it 'only allows the configured origins' do
      expect(Rails.application.config.action_cable.allowed_request_origins).to eq([allowed_origin])
    end
  end
end

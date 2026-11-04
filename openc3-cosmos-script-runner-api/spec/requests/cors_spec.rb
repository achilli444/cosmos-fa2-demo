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

RSpec.describe OpenC3Cors do
  describe "allowed_origins" do
    it "returns no origins when nothing is configured" do
      expect(OpenC3Cors.allowed_origins({})).to eq([])
      expect(OpenC3Cors.allowed_origins({ 'OPENC3_ALLOWED_ORIGINS' => ' , ' })).to eq([])
    end

    it "splits OPENC3_ALLOWED_ORIGINS on commas" do
      env = { 'OPENC3_ALLOWED_ORIGINS' => 'https://cosmos.example.com, http://localhost:2900 ,' }
      expect(OpenC3Cors.allowed_origins(env)).to eq(['https://cosmos.example.com', 'http://localhost:2900'])
    end

    it "falls back to OPENC3_EXTERNAL_URL" do
      env = { 'OPENC3_EXTERNAL_URL' => 'http://localhost:2900' }
      expect(OpenC3Cors.allowed_origins(env)).to eq(['http://localhost:2900'])
    end

    it "prefers OPENC3_ALLOWED_ORIGINS over OPENC3_EXTERNAL_URL" do
      env = { 'OPENC3_ALLOWED_ORIGINS' => 'https://cosmos.example.com', 'OPENC3_EXTERNAL_URL' => 'http://localhost:2900' }
      expect(OpenC3Cors.allowed_origins(env)).to eq(['https://cosmos.example.com'])
    end
  end

  describe "middleware" do
    def cors_app(allowed)
      inner = ->(_env) { [200, { 'content-type' => 'text/plain' }, ['ok']] }
      Rack::Cors.new(inner) { |cors| OpenC3Cors.configure(cors, allowed) }
    end

    def request(allowed, method, origin, headers = {})
      Rack::MockRequest.new(cors_app(allowed)).request(method, '/openc3-api/api', headers.merge('HTTP_ORIGIN' => origin))
    end

    let(:allowed) { ['https://cosmos.example.com'] }

    it "grants a configured origin" do
      response = request(allowed, 'POST', 'https://cosmos.example.com')
      expect(response.headers['Access-Control-Allow-Origin']).to eq('https://cosmos.example.com')
    end

    it "does not grant an unconfigured origin" do
      response = request(allowed, 'POST', 'https://evil.example.com')
      expect(response.headers['Access-Control-Allow-Origin']).to be_nil
    end

    it "does not grant a different scheme or port of a configured origin" do
      expect(request(allowed, 'GET', 'http://cosmos.example.com').headers['Access-Control-Allow-Origin']).to be_nil
      expect(request(allowed, 'GET', 'https://cosmos.example.com:8443').headers['Access-Control-Allow-Origin']).to be_nil
    end

    it "answers preflight only for a configured origin" do
      preflight = { 'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST', 'HTTP_ACCESS_CONTROL_REQUEST_HEADERS' => 'authorization' }
      response = request(allowed, 'OPTIONS', 'https://cosmos.example.com', preflight)
      expect(response.headers['Access-Control-Allow-Origin']).to eq('https://cosmos.example.com')
      expect(response.headers['Access-Control-Allow-Methods']).to include('POST')
      response = request(allowed, 'OPTIONS', 'https://evil.example.com', preflight)
      expect(response.headers['Access-Control-Allow-Origin']).to be_nil
    end

    it "sends no CORS headers when no origins are configured" do
      response = request([], 'POST', 'https://cosmos.example.com')
      expect(response.headers.keys.grep(/Access-Control/i)).to be_empty
    end
  end

  describe "application" do
    it "only installs Rack::Cors when origins are configured" do
      installed = Rails.application.config.middleware.include?(Rack::Cors)
      expect(installed).to eq(!OpenC3Cors.allowed_origins.empty?)
    end
  end
end

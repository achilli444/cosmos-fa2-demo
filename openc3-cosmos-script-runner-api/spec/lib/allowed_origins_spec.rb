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

require 'spec_helper'
require_relative '../../lib/allowed_origins'

RSpec.describe ScriptRunnerApi::AllowedOrigins do
  describe '.origins' do
    it 'parses a comma or whitespace separated OPENC3_ALLOWED_ORIGINS list' do
      env = { 'OPENC3_ALLOWED_ORIGINS' => 'https://cosmos.example.mil, http://localhost:2900 https://ops.example.mil:8443' }
      expect(described_class.origins(env)).to eq(['https://cosmos.example.mil', 'http://localhost:2900', 'https://ops.example.mil:8443'])
    end

    it 'normalizes to scheme://host[:port] dropping default ports, paths and duplicates' do
      env = { 'OPENC3_ALLOWED_ORIGINS' => 'https://cosmos.example.mil:443/tools/, HTTPS://cosmos.example.mil, http://localhost:80' }
      expect(described_class.origins(env)).to eq(['https://cosmos.example.mil', 'http://localhost'])
    end

    it 'falls back to OPENC3_EXTERNAL_URL when OPENC3_ALLOWED_ORIGINS is unset or blank' do
      expect(described_class.origins({ 'OPENC3_EXTERNAL_URL' => 'http://localhost:2900' })).to eq(['http://localhost:2900'])
      expect(described_class.origins({ 'OPENC3_ALLOWED_ORIGINS' => ' ', 'OPENC3_EXTERNAL_URL' => 'http://localhost:2900' })).to eq(['http://localhost:2900'])
    end

    it 'prefers OPENC3_ALLOWED_ORIGINS over OPENC3_EXTERNAL_URL' do
      env = { 'OPENC3_ALLOWED_ORIGINS' => 'https://cosmos.example.mil', 'OPENC3_EXTERNAL_URL' => 'http://localhost:2900' }
      expect(described_class.origins(env)).to eq(['https://cosmos.example.mil'])
    end

    it 'allows nothing when neither variable is set' do
      expect(described_class.origins({})).to eq([])
      expect(described_class.configured?({})).to be false
    end

    it 'never allows a wildcard origin' do
      expect { described_class.origins({ 'OPENC3_ALLOWED_ORIGINS' => '*' }) }.to raise_error(ArgumentError, /http\(s\) URLs/)
    end

    it 'rejects entries that are not http(s) URLs' do
      expect { described_class.origins({ 'OPENC3_ALLOWED_ORIGINS' => 'cosmos.example.mil' }) }.to raise_error(ArgumentError, /http\(s\) URLs/)
      expect { described_class.origins({ 'OPENC3_ALLOWED_ORIGINS' => 'ftp://cosmos.example.mil' }) }.to raise_error(ArgumentError, /http\(s\) URLs/)
      expect { described_class.origins({ 'OPENC3_ALLOWED_ORIGINS' => 'http://bad host' }) }.to raise_error(ArgumentError, /http\(s\) URLs/)
    end
  end

  describe '.hosts' do
    it 'returns the origin hostnames plus the service hostname and loopback' do
      env = { 'OPENC3_ALLOWED_ORIGINS' => 'https://cosmos.example.mil:8443, http://localhost:2900' }
      expect(described_class.hosts(env)).to eq(['cosmos.example.mil', 'localhost', 'openc3-cosmos-script-runner-api', '127.0.0.1', '[::1]'])
    end

    it 'uses OPENC3_SCRIPT_API_HOSTNAME for the service hostname when set' do
      env = { 'OPENC3_EXTERNAL_URL' => 'https://cosmos.example.mil', 'OPENC3_SCRIPT_API_HOSTNAME' => 'script-api.cosmos.svc' }
      expect(described_class.hosts(env)).to include('script-api.cosmos.svc')
      expect(described_class.hosts(env)).not_to include('openc3-cosmos-script-runner-api')
    end

    it 'does not contain a wildcard or empty entry when nothing is configured' do
      expect(described_class.hosts({})).to eq(['openc3-cosmos-script-runner-api', 'localhost', '127.0.0.1', '[::1]'])
    end
  end
end

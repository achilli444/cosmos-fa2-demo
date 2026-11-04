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
require 'openc3'
require 'openc3/script'
require 'openc3/script/queue'

module OpenC3
  describe Script do
    QueueSpecResponse = Struct.new(:status, :body)

    class QueueSpecApi
      attr_reader :requests

      def initialize(responses)
        @responses = responses
        @requests = []
      end

      def request(verb, uri, data: nil, json: false, scope: nil)
        @requests << { verb: verb, uri: uri, data: data.dup }
        status, body = @responses.shift
        QueueSpecResponse.new(status, body)
      end
    end

    let(:hazardous_body) do
      '{"status":"error","type":"HazardousError","hazardous":true,"message":"INST CLEAR is Hazardous",' \
        '"hazardous_description":"Clears counters","target_name":"INST","cmd_name":"CLEAR","id":1.0}'
    end
    let(:success_body) { '{"username":"user","target_name":"INST","cmd_name":"CLEAR","id":1.0}' }

    describe 'queue_exec' do
      it 'executes a non-hazardous command without prompting' do
        $api_server = QueueSpecApi.new([[200, success_body]])
        expect(self).not_to receive(:prompt_for_hazardous)
        result = queue_exec('TEST', 1)
        expect(result['cmd_name']).to eql 'CLEAR'
        expect($api_server.requests.length).to eql 1
        expect($api_server.requests[0][:data]).to eql({ 'id' => 1 })
      end

      it 'prompts for a hazardous command and resends with hazardous_confirmed when accepted' do
        $api_server = QueueSpecApi.new([[409, hazardous_body], [200, success_body]])
        expect(self).to receive(:prompt_for_hazardous).with('INST', 'CLEAR', 'Clears counters').and_return(true)
        result = queue_exec('TEST')
        expect(result['cmd_name']).to eql 'CLEAR'
        expect($api_server.requests.length).to eql 2
        expect($api_server.requests[0][:data]).to eql({})
        expect($api_server.requests[1][:data]).to eql({ 'hazardous_confirmed' => true })
      end

      it 'does not resend a hazardous command when the prompt is declined' do
        $api_server = QueueSpecApi.new([[409, hazardous_body], [200, success_body]])
        expect(self).to receive(:prompt_for_hazardous).and_return(false)
        expect { queue_exec('TEST') }.to raise_error(RuntimeError, /Hazardous command INST CLEAR was not confirmed and remains in queue TEST/)
        expect($api_server.requests.length).to eql 1
      end

      it 'raises other errors as before' do
        $api_server = QueueSpecApi.new([[404, '{"status":"error","message":"No commands in queue TEST"}']])
        expect { queue_exec('TEST') }.to raise_error(RuntimeError, /exec command failed with status 404. No commands in queue TEST/)
      end
    end
  end
end

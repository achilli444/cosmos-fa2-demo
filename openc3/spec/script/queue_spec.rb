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
# See GNU Affero General Public License for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3'
require 'openc3/script'
require 'openc3/script/queue'

module OpenC3
  describe Script do
    describe "queue_exec" do
      before(:each) do
        @api_server = double("api_server")
        $api_server = @api_server
      end

      after(:each) do
        $api_server = nil
      end

      def response(status, body)
        double("response", status: status, body: body)
      end

      it "does not send confirm_hazardous by default" do
        expect(@api_server).to receive(:request).with('post', '/openc3-api/queues/TEST/exec_command',
          data: {}, json: true, scope: 'DEFAULT').and_return(response(200, '{"id":1.0}'))
        expect(queue_exec('TEST')).to eql({ 'id' => 1.0 })
      end

      it "sends confirm_hazardous only when explicitly requested" do
        expect(@api_server).to receive(:request).with('post', '/openc3-api/queues/TEST/exec_command',
          data: { 'id' => 5, 'confirm_hazardous' => true }, json: true, scope: 'DEFAULT').and_return(response(200, '{"id":5.0}'))
        expect(queue_exec('TEST', 5, confirm_hazardous: true)).to eql({ 'id' => 5.0 })
      end

      it "raises with the hazardous message on a 409 refusal" do
        body = '{"status":"error","type":"HazardousError","message":"INST CLEAR with {} is Hazardous due to \'Clears counters\'. Resend with confirm_hazardous=true to acknowledge the hazard."}'
        allow(@api_server).to receive(:request).and_return(response(409, body))
        expect { queue_exec('TEST') }.to raise_error(/exec command failed with status 409. INST CLEAR .* is Hazardous due to 'Clears counters'/)
      end
    end
  end
end

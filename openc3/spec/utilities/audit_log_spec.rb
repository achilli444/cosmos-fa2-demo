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
# See the GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/utilities/audit_log'

module OpenC3
  describe AuditLog do
    class AuditLogTest
      include Authorization
      include AuditLog
    end

    before(:each) do
      @auditor = AuditLogTest.new
      allow(Logger).to receive(:info)
    end

    describe "audit" do
      it "records the user, action, target, params and a success outcome" do
        result = @auditor.audit('connect_interface', target: 'INST_INT', params: ['a', 1], scope: 'DEFAULT', token: nil) { :done }
        expect(result).to eql :done
        expect(Logger).to have_received(:info).with(
          "AUDIT connect_interface target=INST_INT params=[a, 1] outcome=success",
          scope: 'DEFAULT', user: 'anonymous'
        )
      end

      it "records the failure outcome and re-raises" do
        expect {
          @auditor.audit('disable_cmd', target: 'INST ABORT', scope: 'DEFAULT') { raise "boom" }
        }.to raise_error(RuntimeError, "boom")
        expect(Logger).to have_received(:info).with(
          "AUDIT disable_cmd target=INST ABORT outcome=failed: RuntimeError: boom",
          scope: 'DEFAULT', user: 'anonymous'
        )
      end

      it "uses the username resolved from the token" do
        allow(@auditor).to receive(:user_info).with('tok').and_return({ 'username' => 'operator' })
        @auditor.audit('set_tlm', scope: 'DEFAULT', token: 'tok') { nil }
        expect(Logger).to have_received(:info).with("AUDIT set_tlm outcome=success", scope: 'DEFAULT', user: 'operator')
      end

      it "prefers an explicitly supplied user" do
        @auditor.audit('set_tlm', scope: 'DEFAULT', user: 'admin') { nil }
        expect(Logger).to have_received(:info).with("AUDIT set_tlm outcome=success", scope: 'DEFAULT', user: 'admin')
      end
    end

    describe "format_params" do
      it "filters sensitive keys" do
        expect(AuditLog.format_params({ 'name' => 'x', 'password' => 'hunter2', 'api_token' => 'abc' })).to eql(
          "{name=x, password=[FILTERED], api_token=[FILTERED]}"
        )
      end

      it "truncates long values" do
        text = 'a' * 500
        formatted = AuditLog.format_params({ text: text })
        expect(formatted).to include("#{'a' * AuditLog::MAX_PARAM_LENGTH}...(500 chars)")
        expect(formatted).not_to include('a' * (AuditLog::MAX_PARAM_LENGTH + 1))
      end

      it "reduces uploaded files to their filename" do
        upload = double("upload", original_filename: 'plugin.gem')
        expect(AuditLog.format_params({ plugin: upload })).to eql("{plugin=<file plugin.gem>}")
      end
    end
  end
end

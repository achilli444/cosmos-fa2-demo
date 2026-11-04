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
require 'openc3/utilities/security_audit'

module OpenC3
  describe SecurityAudit do
    describe "source_from_headers" do
      it "prefers the first X-Forwarded-For hop" do
        headers = { 'HTTP_X_FORWARDED_FOR' => '10.1.2.3, 172.16.0.1', 'HTTP_X_REAL_IP' => '172.16.0.1' }
        expect(SecurityAudit.source_from_headers(headers)).to eql '10.1.2.3'
      end

      it "falls back to X-Real-IP and REMOTE_ADDR" do
        expect(SecurityAudit.source_from_headers({ 'HTTP_X_REAL_IP' => '10.9.9.9' })).to eql '10.9.9.9'
        expect(SecurityAudit.source_from_headers({ 'REMOTE_ADDR' => '127.0.0.1' })).to eql '127.0.0.1'
      end

      it "returns nil when no address header is present" do
        expect(SecurityAudit.source_from_headers({})).to be_nil
        expect(SecurityAudit.source_from_headers(nil)).to be_nil
        expect(SecurityAudit.source_from_headers({ 'HTTP_X_FORWARDED_FOR' => ' ' })).to be_nil
      end
    end

    describe "with_context" do
      it "merges and restores the per-thread context" do
        expect(SecurityAudit.context).to eql({})
        SecurityAudit.with_context(source: '10.0.0.1', user: 'alice') do
          SecurityAudit.with_context(method: 'tlm') do
            expect(SecurityAudit.context).to eql({ source: '10.0.0.1', user: 'alice', method: 'tlm' })
          end
          expect(SecurityAudit.context).to eql({ source: '10.0.0.1', user: 'alice' })
        end
        expect(SecurityAudit.context).to eql({})
      end

      it "restores the context when the block raises" do
        expect {
          SecurityAudit.with_context(source: '10.0.0.1') { raise "boom" }
        }.to raise_error("boom")
        expect(SecurityAudit.context).to eql({})
      end

      it "does not overwrite outer values with nil" do
        SecurityAudit.with_context(source: '10.0.0.1') do
          SecurityAudit.with_context(source: nil, method: 'cmd') do
            expect(SecurityAudit.context[:source]).to eql '10.0.0.1'
          end
        end
      end
    end

    describe "log" do
      it "writes a structured WARN record for failures with user, source and outcome" do
        capture_io do |stdout|
          SecurityAudit.log(event: 'login', outcome: SecurityAudit::FAILURE, reason: 'Incorrect password',
                            user: 'operator', source: '10.0.0.5', login_type: 'user')
          record = JSON.parse(stdout.string.lines.last)
          expect(record['level']).to eql 'WARN'
          expect(record['type']).to eql 'security'
          expect(record['user']).to eql 'operator'
          expect(record['message']).to include('login failure: Incorrect password')
          expect(record).to include('event' => 'login', 'outcome' => 'failure', 'reason' => 'Incorrect password',
                                    'source' => '10.0.0.5', 'login_type' => 'user')
        end
      end

      it "writes only flat string fields so the record fits in the Redis log stream (XADD)" do
        allow(Logger).to receive(:warn).and_call_original
        SecurityAudit.log(event: 'authorize', outcome: SecurityAudit::FAILURE, reason: 'Token is invalid',
                          scope: 'DEFAULT', permission: :tlm, target_name: nil, count: 3)
        expect(Logger).to have_received(:warn) do |_message, **kwargs|
          expect(kwargs[:other]).to eql({ event: 'authorize', outcome: 'failure', reason: 'Token is invalid',
                                          scope: 'DEFAULT', permission: 'tlm', count: '3' })
          expect(kwargs[:other].values).to all(be_a(String))
        end
      end

      it "writes an INFO record for successes" do
        capture_io do |stdout|
          SecurityAudit.log(event: 'login', outcome: SecurityAudit::SUCCESS, user: 'operator', source: '10.0.0.5')
          record = JSON.parse(stdout.string.lines.last)
          expect(record['level']).to eql 'INFO'
          expect(record['outcome']).to eql 'success'
        end
      end

      it "logs to the requested scope's topic so it shows in that scope's Log Messages" do
        expect(Logger).to receive(:warn).with(/Security event authorize failure/, hash_including(scope: 'DEFAULT', type: 'security'))
        SecurityAudit.log(event: 'authorize', outcome: SecurityAudit::FAILURE, scope: 'DEFAULT')
      end

      it "logs to the NOSCOPE topic when the scope is unknown (e.g. login)" do
        expect(Logger).to receive(:warn).with(/Security event login failure/, hash_including(scope: nil, type: 'security'))
        SecurityAudit.log(event: 'login', outcome: SecurityAudit::FAILURE)
      end

      it "fills user, source and method from the thread context" do
        SecurityAudit.with_context(source: '192.168.1.1', user: 'bob', method: 'cmd') do
          data = SecurityAudit.authorization_failure("Token is invalid", scope: 'DEFAULT', permission: 'cmd')
          expect(data).to eql({
                                event: 'authorize', outcome: 'failure', reason: 'Token is invalid', user: 'bob',
                                source: '192.168.1.1', method: 'cmd', scope: 'DEFAULT', permission: 'cmd'
                              })
        end
      end

      it "defaults the user to anonymous and omits unknown fields" do
        data = SecurityAudit.log(event: 'authorize', outcome: SecurityAudit::FAILURE, reason: 'Scope is required')
        expect(data).to eql({ event: 'authorize', outcome: 'failure', reason: 'Scope is required', user: 'anonymous' })
      end
    end
  end
end

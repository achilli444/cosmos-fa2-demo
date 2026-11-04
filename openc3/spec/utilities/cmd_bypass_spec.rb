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
require 'openc3/utilities/cmd_bypass'

module OpenC3
  describe CmdBypass do
    around(:each) do |example|
      saved = ENV['OPENC3_ALLOW_CMD_BYPASS']
      example.run
    ensure
      ENV['OPENC3_ALLOW_CMD_BYPASS'] = saved
    end

    describe "requested?" do
      it "is true when either check is disabled" do
        expect(CmdBypass.requested?(range_check: false, hazardous_check: true)).to be true
        expect(CmdBypass.requested?(range_check: true, hazardous_check: false)).to be true
        expect(CmdBypass.requested?(range_check: false, hazardous_check: false)).to be true
      end

      it "is false for a normal command and for raw buffers without checks" do
        expect(CmdBypass.requested?(range_check: true, hazardous_check: true)).to be false
        expect(CmdBypass.requested?(range_check: true, hazardous_check: nil)).to be false
      end
    end

    describe "allowed?" do
      it "defaults to false when OPENC3_ALLOW_CMD_BYPASS is unset or blank" do
        ENV.delete('OPENC3_ALLOW_CMD_BYPASS')
        expect(CmdBypass.allowed?).to be false
        ENV['OPENC3_ALLOW_CMD_BYPASS'] = '  '
        expect(CmdBypass.allowed?).to be false
      end

      it "treats 0, false, no and off as disabled" do
        %w(0 false FALSE no Off).each do |value|
          ENV['OPENC3_ALLOW_CMD_BYPASS'] = value
          expect(CmdBypass.allowed?).to be(false), "expected #{value} to disable"
        end
      end

      it "is true for any other value" do
        %w(1 true TRUE yes).each do |value|
          ENV['OPENC3_ALLOW_CMD_BYPASS'] = value
          expect(CmdBypass.allowed?).to be(true), "expected #{value} to enable"
        end
      end
    end

    describe "rejection_message" do
      it "names the command and the ways to permit it" do
        message = CmdBypass.rejection_message('cmd_no_checks("INST ABORT")')
        expect(message).to include('cmd_no_checks("INST ABORT")')
        expect(message).to include('OPENC3_ALLOW_CMD_BYPASS')
        expect(message).to include('critical commanding')
      end
    end
  end
end

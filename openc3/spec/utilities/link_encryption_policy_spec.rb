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
require 'openc3/utilities/link_encryption_policy'
require 'openc3/interfaces/stream_interface'
require 'openc3/interfaces/protocols/aead_protocol'

module OpenC3
  describe LinkEncryptionPolicy do
    before(:each) do
      @saved = ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS']
      ENV.delete('OPENC3_REQUIRE_ENCRYPTED_LINKS')
      @interface = StreamInterface.new
    end

    after(:each) do
      if @saved
        ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = @saved
      else
        ENV.delete('OPENC3_REQUIRE_ENCRYPTED_LINKS')
      end
    end

    it "accepts encrypted transports silently" do
      expect(Logger).not_to receive(:warn)
      expect(@interface.enforce_link_encryption_policy('tls', encrypted: true)).to be true
    end

    it "warns on plaintext links by default" do
      expect(Logger).to receive(:warn).with(/plaintext link host:1234: commands and telemetry are not encrypted/)
      expect(@interface.enforce_link_encryption_policy('host:1234', encrypted: false)).to be false
    end

    it "refuses plaintext links when OPENC3_REQUIRE_ENCRYPTED_LINKS is set" do
      %w[true 1 YES on].each do |value|
        ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = value
        expect { @interface.enforce_link_encryption_policy('host:1234') }.to raise_error(PlaintextLinkError, /refusing plaintext link host:1234/)
      end
    end

    it "does not refuse when OPENC3_REQUIRE_ENCRYPTED_LINKS is false" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'false'
      expect(Logger).to receive(:warn)
      expect(@interface.enforce_link_encryption_policy('host:1234')).to be false
    end

    it "permits an explicitly approved bypass and logs it" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'true'
      @interface.set_option('ALLOW_PLAINTEXT', ['true'])
      expect(Logger).to receive(:warn).with(/permitted by ALLOW_PLAINTEXT/)
      expect(@interface.enforce_link_encryption_policy('host:1234')).to be false
    end

    it "ignores ALLOW_PLAINTEXT false" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'true'
      @interface.set_option('ALLOW_PLAINTEXT', ['false'])
      expect { @interface.enforce_link_encryption_policy('host:1234') }.to raise_error(PlaintextLinkError)
    end

    it "treats an AeadProtocol on both directions as an encrypted link" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'true'
      @interface.add_protocol(AeadProtocol, ['LINK_KEY'], :READ_WRITE)
      expect(Logger).not_to receive(:warn)
      expect(@interface.enforce_link_encryption_policy('host:1234')).to be true
    end

    it "still refuses when only one direction carries the AeadProtocol" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'true'
      @interface.add_protocol(AeadProtocol, ['LINK_KEY'], :READ)
      expect { @interface.enforce_link_encryption_policy('host:1234') }.to raise_error(PlaintextLinkError)
    end

    it "accepts a read only AeadProtocol on a read only interface" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'true'
      @interface.instance_variable_set(:@write_allowed, false)
      @interface.add_protocol(AeadProtocol, ['LINK_KEY'], :READ)
      expect(@interface.enforce_link_encryption_policy('host:1234')).to be true
    end
  end
end

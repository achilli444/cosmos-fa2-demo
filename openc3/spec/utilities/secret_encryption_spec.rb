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
require 'openc3/utilities/secret_encryption'

module OpenC3
  describe SecretEncryption do
    around(:each) do |example|
      saved = ENV['OPENC3_SECRET_ENCRYPTION_KEY']
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = 'ab' * 32
      example.run
    ensure
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = saved
    end

    it "round trips a value through AES-256-GCM" do
      sealed = SecretEncryption.encrypt('hunter2', context: 'DEFAULT__openc3__secrets:PASSWORD')
      expect(sealed).to start_with('enc:v1:')
      expect(sealed).not_to include('hunter2')
      expect(SecretEncryption.decrypt(sealed, context: 'DEFAULT__openc3__secrets:PASSWORD')).to eq('hunter2')
    end

    it "uses a fresh IV per encryption" do
      a = SecretEncryption.encrypt('same', context: 'ctx')
      b = SecretEncryption.encrypt('same', context: 'ctx')
      expect(a).not_to eq(b)
    end

    it "round trips binary data such as certificate files" do
      data = (0..255).map(&:chr).join.b
      sealed = SecretEncryption.encrypt(data, context: 'ctx')
      expect(SecretEncryption.decrypt(sealed, context: 'ctx').b).to eq(data)
    end

    it "rejects a ciphertext moved to another name or scope" do
      sealed = SecretEncryption.encrypt('hunter2', context: 'DEFAULT__openc3__secrets:PASSWORD')
      expect { SecretEncryption.decrypt(sealed, context: 'OTHER__openc3__secrets:PASSWORD') }.to raise_error(SecretEncryption::Error, /tampered/)
    end

    it "rejects a tampered ciphertext" do
      sealed = SecretEncryption.encrypt('hunter2', context: 'ctx')
      parts = sealed.split(':')
      parts[4] = Base64.strict_encode64(Base64.strict_decode64(parts[4]).bytes.map { |b| b ^ 0xFF }.pack('C*'))
      expect { SecretEncryption.decrypt(parts.join(':'), context: 'ctx') }.to raise_error(SecretEncryption::Error)
    end

    it "rejects decryption with a different key" do
      sealed = SecretEncryption.encrypt('hunter2', context: 'ctx')
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = 'cd' * 32
      expect { SecretEncryption.decrypt(sealed, context: 'ctx') }.to raise_error(SecretEncryption::Error)
    end

    it "returns legacy plaintext values unchanged" do
      expect(SecretEncryption.decrypt('plain', context: 'ctx')).to eq('plain')
      expect(SecretEncryption.decrypt(nil, context: 'ctx')).to be_nil
      expect(SecretEncryption.encrypted?('plain')).to be false
    end

    it "refuses to encrypt without a key" do
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = nil
      expect(SecretEncryption.configured?).to be false
      expect { SecretEncryption.encrypt('x', context: 'ctx') }.to raise_error(SecretEncryption::KeyMissingError, /OPENC3_SECRET_ENCRYPTION_KEY/)
    end

    it "rejects a malformed key" do
      ENV['OPENC3_SECRET_ENCRYPTION_KEY'] = 'tooshort'
      expect { SecretEncryption.encrypt('x', context: 'ctx') }.to raise_error(SecretEncryption::Error, /64 hex/)
    end

    it "rejects a malformed envelope" do
      expect { SecretEncryption.decrypt('enc:v1:garbage', context: 'ctx') }.to raise_error(SecretEncryption::Error, /Malformed/)
    end
  end
end

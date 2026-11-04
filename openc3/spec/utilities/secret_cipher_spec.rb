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
require 'openc3/utilities/secret_cipher'
require 'tempfile'

module OpenC3
  describe SecretCipher do
    KEY_HEX = '0000000000000000000000000000000000000000000000000000000000000001'
    AAD = 'DEFAULT__openc3__secrets:PW'

    before(:each) do
      @saved_key = ENV['OPENC3_SECRETS_KEY']
      @saved_file = ENV['OPENC3_SECRETS_KEY_FILE']
      ENV['OPENC3_SECRETS_KEY'] = KEY_HEX
      ENV.delete('OPENC3_SECRETS_KEY_FILE')
    end

    after(:each) do
      ENV['OPENC3_SECRETS_KEY'] = @saved_key
      ENV['OPENC3_SECRETS_KEY_FILE'] = @saved_file
    end

    describe "key" do
      it "reads a hex key from OPENC3_SECRETS_KEY" do
        expect(SecretCipher.key).to eql (("\x00" * 31) + "\x01").b
      end

      it "reads a hex key from OPENC3_SECRETS_KEY_FILE" do
        ENV.delete('OPENC3_SECRETS_KEY')
        Tempfile.create('key') do |f|
          f.write("#{KEY_HEX}\n")
          f.flush
          ENV['OPENC3_SECRETS_KEY_FILE'] = f.path
          expect(SecretCipher.key).to eql (("\x00" * 31) + "\x01").b
        end
      end

      it "reads a raw 32 byte key from OPENC3_SECRETS_KEY_FILE" do
        ENV.delete('OPENC3_SECRETS_KEY')
        Tempfile.create('key', binmode: true) do |f|
          f.write("\xAB".b * 32)
          f.flush
          ENV['OPENC3_SECRETS_KEY_FILE'] = f.path
          expect(SecretCipher.key).to eql("\xAB".b * 32)
        end
      end

      it "fails closed when no key is configured" do
        ENV.delete('OPENC3_SECRETS_KEY')
        expect { SecretCipher.key }.to raise_error(SecretCipher::KeyError, /OPENC3_SECRETS_KEY or OPENC3_SECRETS_KEY_FILE must be set/)
        ENV['OPENC3_SECRETS_KEY'] = ''
        expect { SecretCipher.encrypt('x', aad: AAD) }.to raise_error(SecretCipher::KeyError)
      end

      it "rejects a key that is not 32 bytes of hex" do
        ENV['OPENC3_SECRETS_KEY'] = 'abc'
        expect { SecretCipher.key }.to raise_error(SecretCipher::KeyError, /64 hex characters/)
        ENV['OPENC3_SECRETS_KEY'] = 'zz' * 32
        expect { SecretCipher.key }.to raise_error(SecretCipher::KeyError, /64 hex characters/)
      end

      it "reports an unreadable key file" do
        ENV.delete('OPENC3_SECRETS_KEY')
        ENV['OPENC3_SECRETS_KEY_FILE'] = '/nonexistent/openc3_key'
        expect { SecretCipher.key }.to raise_error(SecretCipher::KeyError, /Unable to read/)
      end
    end

    describe "encrypt / decrypt" do
      it "round trips and never stores the plaintext" do
        envelope = SecretCipher.encrypt('hunter2', aad: AAD)
        expect(envelope['alg']).to eql 'aes-256-gcm'
        expect(envelope['v']).to eql 1
        expect(envelope.values.map(&:to_s).join).not_to include('hunter2')
        expect(Base64.strict_decode64(envelope['iv']).bytesize).to eql 12
        expect(Base64.strict_decode64(envelope['tag']).bytesize).to eql 16
        expect(SecretCipher.decrypt(envelope, aad: AAD)).to eql 'hunter2'
      end

      it "uses a fresh IV for every encryption" do
        a = SecretCipher.encrypt('same', aad: AAD)
        b = SecretCipher.encrypt('same', aad: AAD)
        expect(a['iv']).not_to eql b['iv']
        expect(a['ct']).not_to eql b['ct']
      end

      it "handles empty and multibyte values" do
        expect(SecretCipher.decrypt(SecretCipher.encrypt('', aad: AAD), aad: AAD)).to eql ''
        expect(SecretCipher.decrypt(SecretCipher.encrypt("p\u00e4ssw\u00f6rd\u00e9", aad: AAD), aad: AAD)).to eql "p\u00e4ssw\u00f6rd\u00e9"
      end

      it "rejects a tampered ciphertext" do
        envelope = SecretCipher.encrypt('hunter2', aad: AAD)
        ct = Base64.strict_decode64(envelope['ct'])
        ct.setbyte(0, ct.getbyte(0) ^ 0xFF)
        envelope['ct'] = Base64.strict_encode64(ct)
        expect { SecretCipher.decrypt(envelope, aad: AAD) }.to raise_error(SecretCipher::DecryptError, /tampered/)
      end

      it "rejects a ciphertext moved to another secret name or scope" do
        envelope = SecretCipher.encrypt('hunter2', aad: AAD)
        expect { SecretCipher.decrypt(envelope, aad: 'DEFAULT__openc3__secrets:OTHER') }.to raise_error(SecretCipher::DecryptError)
        expect { SecretCipher.decrypt(envelope, aad: 'OTHER__openc3__secrets:PW') }.to raise_error(SecretCipher::DecryptError)
      end

      it "rejects decryption with the wrong key" do
        envelope = SecretCipher.encrypt('hunter2', aad: AAD)
        ENV['OPENC3_SECRETS_KEY'] = 'ff' * 32
        expect { SecretCipher.decrypt(envelope, aad: AAD) }.to raise_error(SecretCipher::DecryptError, /wrong OPENC3_SECRETS_KEY/)
      end

      it "rejects malformed envelopes" do
        expect { SecretCipher.decrypt('plaintext', aad: AAD) }.to raise_error(SecretCipher::DecryptError, /not an aes-256-gcm envelope/)
        envelope = SecretCipher.encrypt('hunter2', aad: AAD)
        expect { SecretCipher.decrypt(envelope.merge('iv' => '!!'), aad: AAD) }.to raise_error(SecretCipher::DecryptError, /malformed/)
        expect { SecretCipher.decrypt(envelope.merge('tag' => Base64.strict_encode64('short')), aad: AAD) }.to raise_error(SecretCipher::DecryptError, /malformed/)
      end

      it "decrypts an envelope produced by the Python SecretCipher" do
        # Generated by openc3/python/openc3/utilities/secret_cipher.py with KEY_HEX
        envelope = { "v" => 1, "alg" => "aes-256-gcm", "iv" => "61YYVZtTvs38I9Q5", "ct" => "1y4kwq44Ow==", "tag" => "7uI/BKHAFVx7Xs3LF3EReA==" }
        expect(SecretCipher.decrypt(envelope, aad: AAD)).to eql 'hunter2'
      end
    end
  end
end

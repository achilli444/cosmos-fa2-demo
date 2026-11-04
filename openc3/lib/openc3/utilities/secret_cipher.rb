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

require 'openssl'
require 'base64'

module OpenC3
  # Encrypts secret values before they are written to Redis and decrypts them
  # on the way back out, so a Redis dump, backup or read-only connection never
  # yields a usable credential. AES-256-GCM is an authenticated cipher, so a
  # value that was tampered with, or moved to a different secret name or
  # scope, is rejected instead of silently returned.
  #
  # The key never lives in Redis. It is read from OPENC3_SECRETS_KEY (64 hex
  # characters = 32 bytes) or, preferably for mounted secrets, from the file
  # named by OPENC3_SECRETS_KEY_FILE (64 hex characters or 32 raw bytes).
  #
  # The stored form is a Hash so it can be told apart from a legacy plaintext
  # String:
  #   { 'v' => 1, 'alg' => 'aes-256-gcm', 'iv' => <b64>, 'ct' => <b64>, 'tag' => <b64> }
  # openc3/python/openc3/utilities/secret_cipher.py produces and consumes the
  # same format because Ruby and Python microservices share the secret store.
  class SecretCipher
    ALGORITHM = 'aes-256-gcm'
    VERSION = 1
    KEY_BYTES = 32
    IV_BYTES = 12
    TAG_BYTES = 16
    KEY_ENV = 'OPENC3_SECRETS_KEY'
    KEY_FILE_ENV = 'OPENC3_SECRETS_KEY_FILE'

    class KeyError < StandardError; end
    class DecryptError < StandardError; end

    # @return [String] The 32 byte key
    def self.key
      hex = ENV[KEY_ENV]
      if hex.nil? or hex.strip.empty?
        path = ENV[KEY_FILE_ENV]
        if path.nil? or path.strip.empty?
          raise KeyError, "#{KEY_ENV} or #{KEY_FILE_ENV} must be set: the redis secrets " \
                          "backend encrypts secret values at rest with #{ALGORITHM} " \
                          "(generate a key with 'openssl rand -hex #{KEY_BYTES}')"
        end
        begin
          raw = File.binread(path)
        rescue SystemCallError => e
          raise KeyError, "Unable to read #{KEY_FILE_ENV} '#{path}': #{e.message}"
        end
        return raw if raw.bytesize == KEY_BYTES

        hex = raw
      end
      hex = hex.strip
      unless hex.match?(/\A\h{#{KEY_BYTES * 2}}\z/)
        raise KeyError, "#{KEY_ENV} must be #{KEY_BYTES * 2} hex characters " \
                        "(#{KEY_BYTES} bytes), e.g. from 'openssl rand -hex #{KEY_BYTES}'"
      end
      [hex].pack('H*')
    end

    # @return [Boolean] Whether value is an encrypted envelope produced by encrypt
    def self.encrypted?(value)
      value.is_a?(Hash) and value['alg'] == ALGORITHM and value.key?('ct')
    end

    # @param plaintext [String] Secret value
    # @param aad [String] Additional authenticated data bound to the ciphertext
    #   (the secret's scope and name) so an envelope can't be reused elsewhere
    # @return [Hash] Encrypted envelope
    def self.encrypt(plaintext, aad:)
      plaintext = plaintext.to_s.b
      cipher = OpenSSL::Cipher.new(ALGORITHM)
      cipher.encrypt
      cipher.key = key()
      iv = cipher.random_iv
      cipher.auth_data = aad.to_s.b
      ciphertext = plaintext.empty? ? ''.b : cipher.update(plaintext)
      ciphertext << cipher.final
      {
        'v' => VERSION,
        'alg' => ALGORITHM,
        'iv' => Base64.strict_encode64(iv),
        'ct' => Base64.strict_encode64(ciphertext),
        'tag' => Base64.strict_encode64(cipher.auth_tag(TAG_BYTES)),
      }
    end

    # @param envelope [Hash] Envelope produced by encrypt
    # @param aad [String] Must match the value passed to encrypt
    # @return [String] Decrypted secret value
    def self.decrypt(envelope, aad:)
      unless encrypted?(envelope)
        raise DecryptError, "Secret value is not an #{ALGORITHM} envelope"
      end

      begin
        iv = Base64.strict_decode64(envelope['iv'].to_s)
        ciphertext = Base64.strict_decode64(envelope['ct'].to_s)
        tag = Base64.strict_decode64(envelope['tag'].to_s)
      rescue ArgumentError => e
        raise DecryptError, "Secret envelope is malformed: #{e.message}"
      end
      unless iv.bytesize == IV_BYTES and tag.bytesize == TAG_BYTES
        raise DecryptError, "Secret envelope is malformed: bad iv or tag length"
      end

      cipher = OpenSSL::Cipher.new(ALGORITHM)
      cipher.decrypt
      cipher.key = key()
      cipher.iv = iv
      cipher.auth_tag = tag
      cipher.auth_data = aad.to_s.b
      begin
        plaintext = ciphertext.empty? ? ''.b : cipher.update(ciphertext)
        plaintext << cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise DecryptError, "Secret could not be decrypted: wrong #{KEY_ENV} or tampered value"
      end
      plaintext.force_encoding('UTF-8')
    end
  end
end

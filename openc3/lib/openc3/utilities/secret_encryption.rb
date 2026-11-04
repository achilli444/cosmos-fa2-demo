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
  # Encrypts secret values before they are written to Redis so that a Redis
  # dump, backup or read-only Redis access does not expose plugin credentials
  # or Keycloak offline access tokens.
  #
  # Algorithm: AES-256-GCM from the host OpenSSL library (an approved
  # algorithm; the FIPS module validation is inherited from the OpenSSL
  # provider the container ships with). The key is supplied from outside
  # Redis through the OPENC3_SECRET_ENCRYPTION_KEY environment variable as
  # 64 hex characters (32 bytes), e.g. `openssl rand -hex 32`.
  #
  # Stored format (a single string so it fits the existing Model JSON):
  #   enc:v1:<base64 iv>:<base64 tag>:<base64 ciphertext>
  # The Redis primary key and field name are bound in as additional
  # authenticated data so a ciphertext copied to another secret name or
  # scope does not decrypt.
  #
  # Values that do not carry the enc:v1: prefix are treated as legacy
  # plaintext written before encryption existed; they are returned as-is on
  # read and re-encrypted by the EncryptSecrets migration.
  module SecretEncryption
    KEY_ENV = 'OPENC3_SECRET_ENCRYPTION_KEY'
    PREFIX = 'enc:v1:'
    CIPHER = 'aes-256-gcm'
    KEY_BYTES = 32
    IV_BYTES = 12
    TAG_BYTES = 16

    class Error < StandardError; end
    class KeyMissingError < Error; end

    # @return [Boolean] true if an encryption key is available
    def self.configured?
      key = ENV.fetch(KEY_ENV, nil)
      !(key.nil? or key.strip.empty?)
    end

    # @return [Boolean] true if value is in the encrypted envelope format
    def self.encrypted?(value)
      value.is_a?(String) and value.start_with?(PREFIX)
    end

    # @param plaintext [String] value to protect
    # @param context [String] primary key and name the value is stored under
    # @return [String] envelope string safe to store in Redis
    def self.encrypt(plaintext, context:)
      raise ArgumentError, "plaintext must be a String but is a #{plaintext.class}" unless plaintext.is_a?(String)

      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.encrypt
      cipher.key = key
      iv = cipher.random_iv
      cipher.auth_data = context.to_s
      ciphertext = cipher.update(plaintext.b) + cipher.final
      [PREFIX.chomp(':'), encode(iv), encode(cipher.auth_tag(TAG_BYTES)), encode(ciphertext)].join(':')
    end

    # @param value [String, nil] envelope string or legacy plaintext
    # @param context [String] primary key and name the value is stored under
    # @return [String, nil] plaintext
    def self.decrypt(value, context:)
      return value unless encrypted?(value)

      _enc, _version, iv, tag, ciphertext = value.split(':', 5)
      raise Error, "Malformed encrypted secret for #{context}" if iv.nil? or tag.nil? or ciphertext.nil?

      iv = decode(iv)
      tag = decode(tag)
      raise Error, "Malformed encrypted secret for #{context}" if iv.bytesize != IV_BYTES or tag.bytesize != TAG_BYTES

      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_tag = tag
      cipher.auth_data = context.to_s
      plaintext = cipher.update(decode(ciphertext)) + cipher.final
      plaintext.force_encoding('UTF-8')
      plaintext = plaintext.b unless plaintext.valid_encoding?
      plaintext
    rescue OpenSSL::Cipher::CipherError
      raise Error, "Unable to decrypt secret for #{context}: wrong #{KEY_ENV} or tampered value"
    end

    # @return [String] 32 byte key decoded from OPENC3_SECRET_ENCRYPTION_KEY
    def self.key
      raw = ENV.fetch(KEY_ENV, nil)
      if raw.nil? or raw.strip.empty?
        raise KeyMissingError, "#{KEY_ENV} must be set to a 64 character hex string (openssl rand -hex 32) to store or read encrypted secrets"
      end

      raw = raw.strip
      unless raw =~ /\A\h{#{KEY_BYTES * 2}}\z/
        raise Error, "#{KEY_ENV} must be exactly #{KEY_BYTES * 2} hex characters"
      end

      [raw].pack('H*')
    end

    def self.encode(bytes)
      Base64.strict_encode64(bytes)
    end
    private_class_method :encode

    def self.decode(text)
      Base64.strict_decode64(text)
    rescue ArgumentError
      raise Error, 'Malformed encrypted secret'
    end
    private_class_method :decode
  end
end

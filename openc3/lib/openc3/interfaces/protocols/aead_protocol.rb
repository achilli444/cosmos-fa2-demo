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
require 'openc3/config/config_parser'
require 'openc3/interfaces/protocols/protocol'

module OpenC3
  # Authenticated encryption (AES-GCM via OpenSSL) for command and telemetry
  # links. Every write is encrypted into a self-delimiting record and every
  # read is authenticated before the plaintext is handed to later protocols.
  #
  # Record format (all big endian):
  #   [4 byte record length][12 byte nonce][ciphertext][16 byte GCM tag]
  # The record length covers nonce + ciphertext + tag so the protocol can be
  # used directly on byte streams (TCP, serial) as well as message transports.
  #
  # The key never appears in plugin.txt. It is read from the interface secrets
  # (SECRET keyword) by name. FIPS validation of the AES-GCM implementation is
  # inherited from the OpenSSL library the COSMOS containers are built with.
  class AeadProtocol < Protocol
    ERROR = "ERROR" # on authentication failure: log and drop the record
    DISCONNECT = "DISCONNECT" # on authentication failure: disconnect the interface

    CIPHERS = {
      'AES-256-GCM' => 32,
      'AES-128-GCM' => 16,
    }.freeze
    NONCE_LENGTH = 12
    TAG_LENGTH = 16
    LENGTH_FIELD = 4
    # NIST SP 800-38D limits random 96 bit nonces to 2^32 invocations per key
    MAX_RECORDS_PER_KEY = 2**32

    attr_reader :records_written

    # @param key_secret_name [String] Name of the interface SECRET holding the key.
    #   The secret value is either the raw key bytes or the key hex encoded.
    # @param cipher [String] AES-256-GCM (default) or AES-128-GCM
    # @param bad_strategy [ERROR/DISCONNECT] How to handle records that fail authentication
    # @param allow_empty_data [true/false/nil] See Protocol#initialize
    def initialize(key_secret_name, cipher = 'AES-256-GCM', bad_strategy = ERROR, allow_empty_data = nil)
      super(allow_empty_data)
      @key_secret_name = ConfigParser.handle_nil(key_secret_name)
      raise "Key secret name is required" unless @key_secret_name

      @cipher_name = cipher.to_s.upcase
      @key_length = CIPHERS[@cipher_name]
      raise "Invalid cipher '#{cipher}'. Must be one of #{CIPHERS.keys.join(', ')}." unless @key_length

      case bad_strategy
      when ERROR, DISCONNECT
        @bad_strategy = bad_strategy
      else
        raise "Invalid bad strategy of #{bad_strategy}. Must be ERROR or DISCONNECT."
      end
      @key = nil
      @data = ''
      @records_written = 0
    end

    # Marker used by LinkEncryptionPolicy to recognize an encrypted application layer
    def authenticated_encryption?
      true
    end

    def reset
      super()
      @data = ''
    end

    def connect_reset
      super()
      load_key()
    end

    def read_data(data, extra = nil)
      @data << data
      return super(data, extra) if @data.length < LENGTH_FIELD

      record_length = @data[0, LENGTH_FIELD].unpack1('N')
      if record_length < NONCE_LENGTH + TAG_LENGTH
        return bad_record("record length #{record_length} is shorter than nonce + tag")
      end

      return :STOP if @data.length < LENGTH_FIELD + record_length

      record = @data[LENGTH_FIELD, record_length]
      @data.replace(@data[(LENGTH_FIELD + record_length)..-1])
      plaintext = decrypt(record)
      return bad_record("authentication failed") unless plaintext

      return plaintext, extra
    end

    def write_data(data, extra = nil)
      return super(data, extra) if data.length <= 0

      load_key() unless @key
      if @records_written >= MAX_RECORDS_PER_KEY
        raise "#{self.class.name.split('::')[-1]}: #{MAX_RECORDS_PER_KEY} records sent with the same key; rotate the key"
      end

      nonce = OpenSSL::Random.random_bytes(NONCE_LENGTH)
      cipher = OpenSSL::Cipher.new(@cipher_name)
      cipher.encrypt
      cipher.key = @key
      cipher.iv = nonce
      cipher.auth_data = ''
      ciphertext = cipher.update(data) + cipher.final
      tag = cipher.auth_tag(TAG_LENGTH)
      body = nonce + ciphertext + tag
      @records_written += 1
      return [body.length].pack('N') + body, extra
    end

    def write_details
      result = super()
      result['cipher'] = @cipher_name
      result['key_secret_name'] = @key_secret_name
      result['records_written'] = @records_written
      result
    end

    protected

    def decrypt(record)
      nonce = record[0, NONCE_LENGTH]
      tag = record[-TAG_LENGTH..-1]
      ciphertext = record[NONCE_LENGTH...-TAG_LENGTH]
      cipher = OpenSSL::Cipher.new(@cipher_name)
      cipher.decrypt
      cipher.key = @key
      cipher.iv = nonce
      cipher.auth_tag = tag
      cipher.auth_data = ''
      cipher.update(ciphertext) + cipher.final
    rescue OpenSSL::Cipher::CipherError
      nil
    end

    def bad_record(reason)
      name = @interface ? @interface.name : self.class.name.split('::')[-1]
      Logger.error("#{name}: AeadProtocol dropped record: #{reason}")
      if @bad_strategy == DISCONNECT
        @data = ''
        return :DISCONNECT
      end
      # ERROR strategy: the stream may be out of sync so discard buffered bytes
      @data = ''
      return :STOP
    end

    def load_key
      raise "AeadProtocol requires an interface to look up secret '#{@key_secret_name}'" unless @interface

      value = @interface.secrets.get(@key_secret_name, scope: ENV['OPENC3_SCOPE'])
      raise "AeadProtocol secret '#{@key_secret_name}' not found" if value.nil?

      value = value.to_s.strip
      if value.length == @key_length * 2 and value.match?(/\A\h+\z/)
        @key = [value].pack('H*')
      elsif value.bytesize == @key_length
        @key = value.b
      else
        raise "AeadProtocol secret '#{@key_secret_name}' must be #{@key_length} bytes or #{@key_length * 2} hex characters for #{@cipher_name}"
      end
      @records_written = 0
    end
  end
end

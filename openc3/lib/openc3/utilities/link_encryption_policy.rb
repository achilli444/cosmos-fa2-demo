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

require 'openc3/config/config_parser'
require 'openc3/utilities/logger'

module OpenC3
  # Raised when an interface attempts to carry commands or telemetry over a
  # plaintext link while the deployment policy requires encrypted links.
  class PlaintextLinkError < StandardError
  end

  # Deployment-wide policy for command and telemetry links.
  #
  # Every network interface shipped with COSMOS calls {check} from its connect
  # method with a description of the transport and whether that transport is
  # encrypted (TLS) or carries an authenticated-encryption protocol
  # (see {AeadProtocol}). The outcome depends on OPENC3_REQUIRE_ENCRYPTED_LINKS:
  #
  # * unset / false (default, backwards compatible): plaintext links connect but a
  #   warning is logged every time so the unencrypted path is visible in the
  #   audit log.
  # * true / 1 / yes: plaintext links are refused with {PlaintextLinkError}
  #   unless the interface carries OPTION ALLOW_PLAINTEXT true, which records an
  #   explicitly approved bypass. The bypass is still logged as a warning.
  module LinkEncryptionPolicy
    ENV_VAR = 'OPENC3_REQUIRE_ENCRYPTED_LINKS'
    BYPASS_OPTION = 'ALLOW_PLAINTEXT'
    TRUE_VALUES = %w[true 1 yes on].freeze

    # @return [Boolean] Whether plaintext links are refused by policy
    def self.require_encrypted_links?
      TRUE_VALUES.include?(ENV[ENV_VAR].to_s.strip.downcase)
    end

    # @param options [Hash] Interface options hash (see Interface#set_option)
    # @return [Boolean] Whether the interface carries an explicit plaintext bypass
    def self.plaintext_allowed?(options)
      values = options[BYPASS_OPTION]
      return false unless values

      value = values.is_a?(Array) ? values[0] : values
      return true if value.nil? # bare OPTION ALLOW_PLAINTEXT

      ConfigParser.handle_true_false(value) == true
    end

    # @param protocols [Array<Protocol>] Protocol chain to inspect
    # @return [Boolean] Whether the chain contains an authenticated-encryption protocol
    def self.aead_protocol?(protocols)
      protocols.any? do |protocol|
        protocol.respond_to?(:authenticated_encryption?) and protocol.authenticated_encryption?
      end
    end

    # Evaluate the policy for an interface about to connect. Returns true when the
    # link is protected (TLS or AeadProtocol), false when plaintext was permitted
    # (and logged) and raises when the policy refuses the link.
    #
    # @param interface [Interface] The connecting interface
    # @param transport [String] Human readable transport description for the log
    # @param encrypted [Boolean] Whether the transport itself is encrypted (TLS)
    # @raise [PlaintextLinkError] if the policy refuses the plaintext link
    def self.protected_link?(interface, transport, encrypted:)
      return true if encrypted

      read_protected = !interface.read_allowed? || aead_protocol?(interface.read_protocols)
      write_protected = !interface.write_allowed? || aead_protocol?(interface.write_protocols)
      return true if read_protected and write_protected

      name = interface.name
      if plaintext_allowed?(interface.options)
        Logger.warn("#{name}: plaintext link #{transport} permitted by #{BYPASS_OPTION} (approved cryptographic bypass); commands and telemetry are not encrypted on this link")
        return false
      end

      if require_encrypted_links?
        raise PlaintextLinkError, "#{name}: refusing plaintext link #{transport}: #{ENV_VAR} is set. Enable TLS, add an authenticated encryption PROTOCOL (e.g. AeadProtocol), or record an approved bypass with OPTION #{BYPASS_OPTION} true"
      end

      Logger.warn("#{name}: plaintext link #{transport}: commands and telemetry are not encrypted on this link (set #{ENV_VAR}=true to refuse plaintext links)")
      return false
    end
  end
end

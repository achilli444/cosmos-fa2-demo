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

require 'digest'
require 'rubygems'
require 'rubygems/security'
require 'openc3/utilities/logger'

module OpenC3
  class PackageIntegrityError < StandardError; end

  # Integrity gate for every gem and Python package COSMOS installs, whether it
  # was uploaded through the Admin tool, loaded by openc3cli, or pulled from a
  # package index while resolving dependencies.
  #
  # Settings (all read from ENV so they are fixed at deploy time rather than
  # editable from the Admin Settings tab):
  #
  #   OPENC3_GEM_SECURITY_POLICY  RubyGems trust policy applied to every gem that
  #                               is installed or extracted. One of NoSecurity,
  #                               AlmostNoSecurity, LowSecurity, MediumSecurity
  #                               (default) or HighSecurity. MediumSecurity
  #                               verifies the signature chain of any signed gem
  #                               against the trust store; HighSecurity also
  #                               rejects unsigned gems.
  #   OPENC3_GEM_TRUST_DIR        Directory holding the trusted signing
  #                               certificates (the managed trust store). Defaults
  #                               to RubyGems' ~/.gem/trust.
  #   OPENC3_PACKAGE_ALLOWLIST    Path to a file of approved SHA-256 digests in
  #                               `sha256sum` format (one "<digest>  <filename>"
  #                               per line, '#' comments allowed). When set, a gem
  #                               or Python package whose digest is not listed is
  #                               rejected before it is cached, extracted or
  #                               installed.
  #
  # Every verified artifact is logged with its SHA-256 so the install record
  # carries the digest that was checked.
  class PackageIntegrity
    DEFAULT_GEM_SECURITY_POLICY = 'MediumSecurity'
    GEM_SECURITY_POLICIES = {
      'NoSecurity' => Gem::Security::NoSecurity,
      'AlmostNoSecurity' => Gem::Security::AlmostNoSecurity,
      'LowSecurity' => Gem::Security::LowSecurity,
      'MediumSecurity' => Gem::Security::MediumSecurity,
      'HighSecurity' => Gem::Security::HighSecurity,
    }.freeze

    # @return [Gem::Security::Policy] the policy to pass to Gem.install and
    #   Gem::Package.new. Raises PackageIntegrityError on an unknown name so a
    #   typo in the deployment config fails closed rather than silently
    #   installing with no policy.
    def self.gem_security_policy
      name = ENV.fetch('OPENC3_GEM_SECURITY_POLICY', DEFAULT_GEM_SECURITY_POLICY).strip
      name = DEFAULT_GEM_SECURITY_POLICY if name.empty?
      policy = GEM_SECURITY_POLICIES[name]
      unless policy
        raise PackageIntegrityError, "Unknown OPENC3_GEM_SECURITY_POLICY '#{name}' (expected one of #{GEM_SECURITY_POLICIES.keys.join(', ')})"
      end

      configure_gem_trust_dir()
      policy
    end

    # Point RubyGems at the managed trust store when one is configured
    def self.configure_gem_trust_dir
      trust_dir = ENV.fetch('OPENC3_GEM_TRUST_DIR', nil)
      return nil if trust_dir.nil? || trust_dir.strip.empty?

      unless Gem::Security.trust_dir.dir == trust_dir
        # Gem::Security memoizes the trust dir in @trust_dir and exposes no setter
        Gem::Security.instance_variable_set(:@trust_dir, Gem::Security::TrustDir.new(trust_dir))
      end
      trust_dir
    end

    # @return [String, nil] path of the digest allow-list, nil when not enforced
    def self.allowlist_path
      path = ENV.fetch('OPENC3_PACKAGE_ALLOWLIST', nil)
      return nil if path.nil? || path.strip.empty?

      path
    end

    # @return [Set<String>] lowercase hex SHA-256 digests approved for install.
    #   Raises PackageIntegrityError when the configured file can't be read so a
    #   missing allow-list blocks installs instead of allowing everything.
    def self.allowed_digests
      path = allowlist_path()
      return nil unless path

      digests = Set.new
      begin
        File.foreach(path) do |line|
          line = line.sub(/#.*/, '').strip
          next if line.empty?

          digest = line.split(/\s+/, 2)[0].downcase
          unless digest.match?(/\A[0-9a-f]{64}\z/)
            raise PackageIntegrityError, "Malformed SHA-256 digest '#{digest}' in #{path}"
          end

          digests << digest
        end
      rescue SystemCallError => e
        raise PackageIntegrityError, "Cannot read OPENC3_PACKAGE_ALLOWLIST #{path}: #{e.message}"
      end
      digests
    end

    # @return [String] lowercase hex SHA-256 of the file
    def self.sha256(path)
      Digest::SHA256.file(path).hexdigest.downcase
    end

    # Verify a package artifact before it is cached, extracted or installed.
    # Logs the digest, enforces the allow-list when configured, and returns the
    # digest so callers can include it in their own install record.
    #
    # @param path [String] gem or Python package file
    # @param scope [String, nil] scope for the log entry
    # @return [String] the verified SHA-256 digest
    def self.verify!(path, scope: nil)
      filename = File.basename(path)
      digest = sha256(path)
      allowed = allowed_digests()
      if allowed and !allowed.include?(digest)
        message = "Package #{filename} rejected: sha256=#{digest} is not in OPENC3_PACKAGE_ALLOWLIST #{allowlist_path()}"
        Logger.error(message, scope: scope)
        raise PackageIntegrityError, message
      end
      Logger.info("Verified package #{filename} sha256=#{digest}#{allowed ? ' (allow-listed)' : ''}", scope: scope)
      digest
    end
  end
end

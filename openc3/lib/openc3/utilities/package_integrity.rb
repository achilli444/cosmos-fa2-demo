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
require 'openc3/utilities/logger'

module OpenC3
  class PackageIntegrityError < StandardError; end

  # Verifies the integrity of plugin gems and Python packages before they are
  # installed and executed inside COSMOS. The uploaded file's SHA-256 must appear
  # in an operator-provisioned allow-list that is distributed separately from the
  # package itself (a file in the image or a mounted volume), never through the
  # API that accepts the upload.
  #
  # OPENC3_PACKAGE_ALLOWLIST  - File::PATH_SEPARATOR separated list of allow-list
  #                             files in `sha256sum` format ("<hex>  <filename>",
  #                             bare digests and '#' comments are also accepted).
  #                             Defaults to DEFAULT_ALLOWLIST_PATH when that file exists.
  # OPENC3_PACKAGE_INTEGRITY  - 'enforce' (default) rejects packages that are not
  #                             allow-listed. 'audit' only logs the rejection, for
  #                             staged rollouts. Any other value is treated as 'enforce'.
  module PackageIntegrity
    DEFAULT_ALLOWLIST_PATH = '/openc3/package_allowlist.sha256'
    DIGEST_PATTERN = /\A[0-9a-f]{64}\z/
    MODES = ['enforce', 'audit'].freeze

    def self.mode
      value = ENV['OPENC3_PACKAGE_INTEGRITY'].to_s.strip.downcase
      MODES.include?(value) ? value : 'enforce'
    end

    def self.enforcing?
      mode == 'enforce'
    end

    def self.allowlist_paths
      env = ENV['OPENC3_PACKAGE_ALLOWLIST']
      if env.nil? || env.strip.empty?
        return File.file?(DEFAULT_ALLOWLIST_PATH) ? [DEFAULT_ALLOWLIST_PATH] : []
      end

      env.split(File::PATH_SEPARATOR).map(&:strip).reject(&:empty?)
    end

    # @return [Set<String>] lowercase hex SHA-256 digests from every allow-list file
    def self.allowed_digests
      digests = Set.new
      allowlist_paths.each do |path|
        unless File.file?(path)
          Logger.error "Package allow-list #{path} does not exist"
          next
        end
        File.foreach(path) do |line|
          entry = line.sub(/#.*\z/, '').strip
          next if entry.empty?

          digest = entry.split(/\s+/, 2)[0].to_s.downcase
          if digest.match?(DIGEST_PATTERN)
            digests << digest
          else
            Logger.error "Ignoring malformed package allow-list entry in #{path}: #{line.strip.inspect}"
          end
        end
      end
      digests
    end

    def self.sha256(path)
      Digest::SHA256.file(path).hexdigest.downcase
    end

    def self.allowed?(path)
      allowed_digests.include?(sha256(path))
    end

    # Raises PackageIntegrityError (in enforce mode) when the file's SHA-256 is
    # not in the allow-list. Returns the digest on success.
    def self.verify!(path)
      raise PackageIntegrityError, "Package file #{path} does not exist" unless File.file?(path)

      digest = sha256(path)
      filename = File.basename(path)
      if allowed_digests.include?(digest)
        Logger.info "Package integrity verified: #{filename} sha256=#{digest}"
        return digest
      end

      message = "Package integrity check failed: #{filename} sha256=#{digest} is not in the package allow-list " \
                "(OPENC3_PACKAGE_ALLOWLIST=#{allowlist_paths.join(File::PATH_SEPARATOR).inspect}). " \
                "Add the digest to an allow-list file to approve this package."
      if enforcing?
        Logger.error message
        raise PackageIntegrityError, message
      end
      Logger.warn "#{message} Installing anyway because OPENC3_PACKAGE_INTEGRITY=audit."
      digest
    end
  end
end

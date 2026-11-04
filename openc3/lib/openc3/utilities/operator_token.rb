# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software: you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/utilities/authentication'
require 'openc3/models/offline_access_model'

module OpenC3
  # Raised when the caller presented no credential that could identify the operator
  class NoOperatorTokenError < OpenC3AuthenticationError; end

  # Resolves the credential an automated command path (script spawn, queue
  # release) runs under. The credential is always the initiating operator's
  # own identity: the token presented on the request in Core, or the
  # operator's offline access token in Enterprise. There is deliberately no
  # fallback to the shared OPENC3_SERVICE_PASSWORD identity, so every command
  # these paths generate is authorized and attributed as the operator.
  module OperatorToken
    # Returns the operator's own request token for use by in-process API
    # calls made on the operator's behalf (e.g. queue release).
    #
    # @param request_token [String] value of the request Authorization header
    # @return [String] the token to pass to the API
    # @raise [NoOperatorTokenError] if the request carried no token
    def self.for_request(request_token)
      token = request_token.to_s.strip
      raise NoOperatorTokenError, "No operator token on request" if token.empty?

      token
    end

    # Returns the environment variables a spawned script process needs to
    # authenticate as the initiating operator.
    #
    # Enterprise: the operator's offline access token (OPENC3_API_TOKEN),
    # validated against Keycloak before use. Core: the operator's own request
    # token, consumed by OpenC3Authentication without a password exchange.
    #
    # @param request_token [String, nil] value of the request Authorization header
    # @param username [String] initiating operator
    # @param scope [String] scope the operator is acting in
    # @return [Hash<String, String>] environment to merge into the child process
    # @raise [NoOperatorTokenError] if no operator credential is available
    # @raise [OpenC3AuthenticationError] if the offline access token is no longer valid
    def self.script_environment(request_token, username:, scope:)
      model = nil
      if username and !username.empty? and username.downcase != 'anonymous'
        model = OfflineAccessModel.get_model(name: username, scope: scope)
      end
      if model and model.offline_access_token
        auth = OpenC3KeycloakAuthentication.new(ENV.fetch('OPENC3_KEYCLOAK_URL', nil))
        unless auth.get_token_from_refresh_token(model.offline_access_token)
          model.offline_access_token = nil
          model.update
          raise OpenC3AuthenticationError, "offline_access token invalid for script"
        end
        return { 'OPENC3_API_TOKEN' => model.offline_access_token }
      end

      if ENV['OPENC3_API_CLIENT']
        raise NoOperatorTokenError,
              "No offline access token for #{username}; initialize offline access before running scripts"
      end

      token = request_token.to_s.strip
      raise NoOperatorTokenError, "No operator token available for script" if token.empty?

      { 'OPENC3_API_PASSWORD' => token }
    end
  end
end

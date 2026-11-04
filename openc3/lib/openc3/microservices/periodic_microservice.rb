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

require 'openc3/microservices/microservice'
require 'openc3/models/offline_access_model'
require 'openc3/models/news_model'
require 'openc3/api/settings_api'

module OpenC3
  class PeriodicMicroservice < Microservice
    include Api

    STARTUP_DELAY_SECONDS = 2 * 60 # Two Minutes
    SLEEP_PERIOD_SECONDS = 24 * 60 * 60 # Run once per day

    def initialize(*args)
      super(*args)
      @metric.set(name: 'periodic_total', value: @count, type: 'counter')
      get_news()
    end

    # Only contacts the news site when the operator has opted in (news_feed
    # setting true). The default is off, so an unconfigured install makes no
    # outbound request.
    def get_news
      return unless NewsModel.enabled?(scope: @scope)

      NewsModel.update()
    end

    def run
      @run_sleeper = Sleeper.new
      return if @run_sleeper.sleep(STARTUP_DELAY_SECONDS)
      while true
        models = OfflineAccessModel.get_all_models(scope: @scope)
        models.each do |name, model|
          if model.offline_access_token
            auth = OpenC3KeycloakAuthentication.new(ENV['OPENC3_KEYCLOAK_URL'])
            valid_token = auth.get_token_from_refresh_token(model.offline_access_token)
            if valid_token
              @logger.info("Refreshed offline access token for #{name}")
              model.offline_access_token = auth.refresh_token
            else
              @logger.error("Unable to refresh offline access token for #{name}")
              model.offline_access_token = nil
            end
            model.update
          end
        end
        @count += 1
        @metric.set(name: 'periodic_total', value: @count, type: 'counter')
        break if @cancel_thread
        break if @run_sleeper.sleep(SLEEP_PERIOD_SECONDS)
        get_news()
      end
    end

    def shutdown
      @run_sleeper.cancel if @run_sleeper
      super()
    end
  end
end

if __FILE__ == $0
  OpenC3::PeriodicMicroservice.run
  OpenC3::ThreadManager.instance.shutdown
  OpenC3::ThreadManager.instance.join
end
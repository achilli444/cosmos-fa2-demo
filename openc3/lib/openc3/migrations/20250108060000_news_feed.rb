require 'openc3/utilities/migration'
require 'openc3/models/scope_model'
require 'openc3/models/setting_model'

module OpenC3
  class NewsFeed < Migration
    # The news feed is opt-in. Only create the setting (off) when an upgraded
    # install has never set it, so an explicit choice is never overwritten.
    def self.run
      return if SettingModel.get(name: 'news_feed', scope: 'DEFAULT')

      SettingModel.set({ name: 'news_feed', data: false }, scope: 'DEFAULT')
    end
  end
end

unless ENV['OPENC3_NO_MIGRATE']
  OpenC3::NewsFeed.run
end

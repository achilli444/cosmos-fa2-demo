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
require 'openc3/microservices/periodic_microservice'
require 'openc3/models/news_model'

# Override at_exit to do nothing for testing
saved_verbose = $VERBOSE; $VERBOSE = nil
def at_exit(*, &)
end
$VERBOSE = saved_verbose

module OpenC3
  describe PeriodicMicroservice do
    before(:each) do
      mock_redis()
      setup_system()
      allow(Metric).to receive(:new).and_return(double('metric').as_null_object)
      allow(MicroserviceStatusModel).to receive(:set).with(any_args)
    end

    after(:each) do
      if @pm
        @pm.shutdown()
        @pm.instance_variable_get(:@microservice_status_thread)&.join
      end
    end

    def start
      @pm = PeriodicMicroservice.new("DEFAULT__PERIODIC__PERIODIC")
    end

    describe "get_news" do
      it "makes no outbound request when news_feed was never set (the default)" do
        expect(Faraday).not_to receive(:new)
        start()
        expect(NewsModel.all()).to be_nil
      end

      it "makes no outbound request when news_feed is false" do
        SettingModel.set({ name: 'news_feed', data: false }, scope: 'DEFAULT')
        expect(Faraday).not_to receive(:new)
        start()
        expect(NewsModel.all()).to be_nil
      end

      it "fetches the feed once the operator opts in, sending no version details" do
        SettingModel.set({ name: 'news_feed', data: true }, scope: 'DEFAULT')
        response = double('response', success?: true, body: '[{"title":"news"}]')
        conn = double('conn')
        expect(Faraday).to receive(:new).with(url: 'https://news.openc3.com').and_return(conn)
        expect(conn).to receive(:get).with('/news').and_return(response)
        start()
        expect(NewsModel.all()).to eql '[{"title":"news"}]'
      end
    end
  end
end

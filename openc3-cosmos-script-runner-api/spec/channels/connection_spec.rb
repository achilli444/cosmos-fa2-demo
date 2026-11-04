# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require "rails_helper"

RSpec.describe ApplicationCable::Connection, type: :channel do
  URL_AUTH_ENV = ApplicationCable::Connection::URL_AUTH_ENV
  SESSION_TOKEN = "ses_#{'a' * 22}"

  def with_env(name, value)
    saved = ENV[name]
    value.nil? ? ENV.delete(name) : ENV[name] = value
    yield
  ensure
    saved.nil? ? ENV.delete(name) : ENV[name] = saved
  end

  before(:each) do
    allow(OpenC3::AuthModel).to receive(:verify).and_return(true)
  end

  it "connects without a token and leaves authentication to the channel subscription" do
    connect "/cable?scope=DEFAULT"
    expect(connection.uuid).to be_a(String) # Any random string will do
    expect(connection.scope).to eq('DEFAULT')
    expect(connection.url_authenticated).to be_falsey # anycable identifiers drop false to nil
  end

  it "rejects a token on the URL query string by default" do
    with_env(URL_AUTH_ENV, nil) do
      expect { connect "/cable?scope=DEFAULT&authorization=#{SESSION_TOKEN}" }.to have_rejected_connection
    end
  end

  it "rejects the URL token path unless the setting is exactly enabled" do
    %w[false 0 yes].each do |value|
      with_env(URL_AUTH_ENV, value) do
        expect(ApplicationCable::Connection.url_auth_allowed?).to be false
      end
    end
  end

  context "with #{URL_AUTH_ENV}=true (legacy opt-in)" do
    around(:each) do |example|
      with_env(URL_AUTH_ENV, 'true') { example.run }
    end

    it "authenticates the whole connection from the URL token" do
      connect "/cable?scope=DEFAULT&authorization=#{SESSION_TOKEN}"
      expect(connection.uuid).to be_a(String)
      expect(connection.url_authenticated).to be true
    end

    it "rejects an invalid URL token" do
      $openc3_authorize = true
      allow(OpenC3::AuthModel).to receive(:verify).and_return(false)
      expect { connect "/cable?scope=DEFAULT&authorization=#{SESSION_TOKEN}" }.to have_rejected_connection
    ensure
      $openc3_authorize = false
    end

    it "rejects the service password even though it passes AuthModel.verify" do
      service_password = ENV.fetch('OPENC3_SERVICE_PASSWORD')
      expect(OpenC3::AuthModel.verify(service_password)).to be true
      expect { connect "/cable?scope=DEFAULT&authorization=#{service_password}" }.to have_rejected_connection
    end
  end
end

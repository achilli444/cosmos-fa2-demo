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

require 'rails_helper'

RSpec.describe AllScriptsChannel, type: :channel do
  before(:each) do
    mock_redis
  end

  it 'streams only the script activity of the authorized scope' do
    # Connections without the url_authenticated identifier are treated as
    # authenticated (see ApplicationCable::Channel#connection_url_authenticated?)
    stub_connection uuid: 'test-uuid', scope: 'DEFAULT'
    subscribe
    expect(subscription).to be_confirmed
    expect(subscription).to have_stream_from('script-api:all-scripts-channel:DEFAULT')
    expect(subscription).not_to have_stream_from('script-api:all-scripts-channel')
    expect(subscription).not_to have_stream_from('script-api:all-scripts-channel:OTHER')
  end

  it 'rejects a connection without a scope' do
    stub_connection uuid: 'test-uuid', scope: nil
    subscribe
    expect(subscription).to be_rejected
    expect(subscription.streams).to be_empty
  end

  it 'rejects a connection with a blank scope' do
    stub_connection uuid: 'test-uuid', scope: ''
    subscribe
    expect(subscription).to be_rejected
    expect(subscription.streams).to be_empty
  end
end

# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require "spec_helper"
require "openc3/utilities/store"

module OpenC3
  describe Store do
    describe "build_redis" do
      # A transient network blip (the same kind that makes targets reconnect)
      # must be retried inside the client with jittered backoff instead of
      # immediately surfacing a connection error to callers, which would
      # otherwise propagate up and kill the caller (e.g. the operator).
      it "configures equal-jitter reconnect backoff mirroring Python" do
        captured = nil
        allow(Redis).to receive(:new) do |**kwargs|
          captured = kwargs
          double("redis").as_null_object
        end

        store = Store.allocate
        store.instance_variable_set(:@redis_url, "redis://localhost:6379")
        store.instance_variable_set(:@redis_username, nil)
        store.instance_variable_set(:@redis_key, nil)
        store.send(:build_redis)

        attempts = captured[:reconnect_attempts]
        expect(attempts.length).to eq(3)
        # Equal-jitter ranges per retry with cap=5, base=0.625:
        # t = min(cap, base*2**f); delay in [t/2, t]
        expect(attempts[0]).to be_between(0.625, 1.25)
        expect(attempts[1]).to be_between(1.25, 2.5)
        expect(attempts[2]).to be_between(2.5, 5.0) # final retry caps at 5s
      end

      it "samples fresh jittered delays each call to de-sync clients" do
        store = Store.allocate
        a = store.send(:reconnect_backoff_delays)
        b = store.send(:reconnect_backoff_delays)
        # Astronomically unlikely to be identical unless jitter is missing
        expect(a).not_to eq(b)
      end
    end

    describe "transport security" do
      around(:each) do |example|
        saved = ENV.to_h.slice('OPENC3_PLAINTEXT_TRANSPORT', 'OPENC3_TLS_CA_FILE', 'OPENC3_REDIS_HOSTNAME', 'OPENC3_REDIS_EPHEMERAL_HOSTNAME')
        ENV.delete('OPENC3_PLAINTEXT_TRANSPORT')
        ENV.delete('OPENC3_TLS_CA_FILE')
        ENV['OPENC3_REDIS_HOSTNAME'] = 'openc3-redis'
        ENV['OPENC3_REDIS_EPHEMERAL_HOSTNAME'] = 'openc3-redis-ephemeral'
        example.run
      ensure
        ENV.delete('OPENC3_PLAINTEXT_TRANSPORT')
        ENV.delete('OPENC3_TLS_CA_FILE')
        ENV.delete('OPENC3_REDIS_HOSTNAME')
        ENV.delete('OPENC3_REDIS_EPHEMERAL_HOSTNAME')
        ENV.update(saved)
      end

      def capture_redis_options(klass)
        captured = nil
        allow(Redis).to receive(:new) do |**kwargs|
          captured = kwargs
          double("redis").as_null_object
        end
        allow(StoreConnectionPool).to receive(:new) { |**_kwargs, &block| block.call; double("pool").as_null_object }
        klass.new(1)
        captured
      end

      it "connects with rediss:// and peer verification by default" do
        options = capture_redis_options(Store)
        expect(options[:url]).to eq "rediss://openc3-redis:6379"
        expect(options[:ssl_params]).to eq({ verify_mode: OpenSSL::SSL::VERIFY_PEER })

        options = capture_redis_options(EphemeralStore)
        expect(options[:url]).to eq "rediss://openc3-redis-ephemeral:6380"
        expect(options[:ssl_params]).to eq({ verify_mode: OpenSSL::SSL::VERIFY_PEER })
      end

      it "pins the CA bundle from OPENC3_TLS_CA_FILE" do
        ENV['OPENC3_TLS_CA_FILE'] = '/etc/openc3/ca.pem'
        options = capture_redis_options(Store)
        expect(options[:ssl_params]).to eq({ verify_mode: OpenSSL::SSL::VERIFY_PEER, ca_file: '/etc/openc3/ca.pem' })
      end

      it "falls back to redis:// only when OPENC3_PLAINTEXT_TRANSPORT is set" do
        ENV['OPENC3_PLAINTEXT_TRANSPORT'] = '1'
        options = capture_redis_options(Store)
        expect(options[:url]).to eq "redis://openc3-redis:6379"
        expect(options).not_to have_key(:ssl_params)
      end
    end
  end
end

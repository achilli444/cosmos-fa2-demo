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

    # Redis carries commands, telemetry, AUTH passwords and secret values, so
    # SC-8 / SC-8(1) hardened deployments need the link encrypted and the
    # server verified. TLS is opt-in so existing plaintext deployments are
    # unchanged, but once enabled verification can never be turned off.
    describe "TLS" do
      def capture_redis_new(store)
        captured = nil
        allow(Redis).to receive(:new) do |**kwargs|
          captured = kwargs
          double("redis").as_null_object
        end
        store.send(:build_redis)
        captured
      end

      def tls_env(overrides = {})
        {
          'OPENC3_REDIS_TLS' => nil,
          'OPENC3_REDIS_TLS_CA_FILE' => nil,
          'OPENC3_REDIS_TLS_CERT_FILE' => nil,
          'OPENC3_REDIS_TLS_KEY_FILE' => nil,
          'OPENC3_REDIS_HOSTNAME' => 'redis-host',
          'OPENC3_REDIS_PORT' => '6379',
          'OPENC3_REDIS_EPHEMERAL_HOSTNAME' => 'redis-eph',
          'OPENC3_REDIS_EPHEMERAL_PORT' => '6380',
        }.merge(overrides)
      end

      it "defaults to plaintext redis:// without ssl_params" do
        stub_const('ENV', ENV.to_h.merge(tls_env))
        allow(StoreConnectionPool).to receive(:new)
        store = Store.new(1)
        expect(store.instance_variable_get(:@redis_url)).to eq("redis://redis-host:6379")
        captured = capture_redis_new(store)
        expect(captured[:url]).to eq("redis://redis-host:6379")
        expect(captured).not_to have_key(:ssl_params)
      end

      ['1', 'true', 'TRUE', 'yes', 'on'].each do |value|
        it "uses rediss:// with peer verification when OPENC3_REDIS_TLS=#{value}" do
          stub_const('ENV', ENV.to_h.merge(tls_env('OPENC3_REDIS_TLS' => value)))
          allow(StoreConnectionPool).to receive(:new)
          store = Store.new(1)
          captured = capture_redis_new(store)
          expect(captured[:url]).to eq("rediss://redis-host:6379")
          expect(captured[:ssl_params][:verify_mode]).to eq(OpenSSL::SSL::VERIFY_PEER)
          # No CA file configured: fall back to the system CA store
          expect(captured[:ssl_params]).not_to have_key(:ca_file)
        end
      end

      ['', '0', 'false', 'off'].each do |value|
        it "stays plaintext when OPENC3_REDIS_TLS=#{value.inspect}" do
          stub_const('ENV', ENV.to_h.merge(tls_env('OPENC3_REDIS_TLS' => value)))
          allow(StoreConnectionPool).to receive(:new)
          store = Store.new(1)
          expect(store.instance_variable_get(:@redis_url)).to eq("redis://redis-host:6379")
          expect(capture_redis_new(store)).not_to have_key(:ssl_params)
        end
      end

      it "verifies the server against OPENC3_REDIS_TLS_CA_FILE" do
        stub_const('ENV', ENV.to_h.merge(tls_env('OPENC3_REDIS_TLS' => '1',
                                                 'OPENC3_REDIS_TLS_CA_FILE' => '/certs/ca.crt')))
        allow(StoreConnectionPool).to receive(:new)
        captured = capture_redis_new(Store.new(1))
        expect(captured[:ssl_params]).to eq(ca_file: '/certs/ca.crt', verify_mode: OpenSSL::SSL::VERIFY_PEER)
      end

      it "passes a client certificate and key for mutual TLS" do
        stub_const('ENV', ENV.to_h.merge(tls_env('OPENC3_REDIS_TLS' => '1',
                                                 'OPENC3_REDIS_TLS_CA_FILE' => '/certs/ca.crt',
                                                 'OPENC3_REDIS_TLS_CERT_FILE' => '/certs/client.crt',
                                                 'OPENC3_REDIS_TLS_KEY_FILE' => '/certs/client.key')))
        allow(StoreConnectionPool).to receive(:new)
        captured = capture_redis_new(Store.new(1))
        expect(captured[:ssl_params]).to eq(
          ca_file: '/certs/ca.crt',
          cert: '/certs/client.crt',
          key: '/certs/client.key',
          verify_mode: OpenSSL::SSL::VERIFY_PEER
        )
      end

      it "rejects a client certificate without its key" do
        stub_const('ENV', ENV.to_h.merge(tls_env('OPENC3_REDIS_TLS' => '1',
                                                 'OPENC3_REDIS_TLS_CERT_FILE' => '/certs/client.crt')))
        allow(StoreConnectionPool).to receive(:new)
        store = Store.new(1)
        expect { store.send(:build_redis) }.to raise_error(/must be set together/)
      end

      it "applies TLS to the EphemeralStore as well" do
        stub_const('ENV', ENV.to_h.merge(tls_env('OPENC3_REDIS_TLS' => '1',
                                                 'OPENC3_REDIS_TLS_CA_FILE' => '/certs/ca.crt')))
        allow(StoreConnectionPool).to receive(:new)
        store = EphemeralStore.new(1)
        expect(store.instance_variable_get(:@redis_url)).to eq("rediss://redis-eph:6380")
        captured = capture_redis_new(store)
        expect(captured[:url]).to eq("rediss://redis-eph:6380")
        expect(captured[:ssl_params][:verify_mode]).to eq(OpenSSL::SSL::VERIFY_PEER)
        expect(captured[:ssl_params][:ca_file]).to eq('/certs/ca.crt')
      end
    end
  end
end

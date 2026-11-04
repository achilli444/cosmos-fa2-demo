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
require 'openc3/utilities/tls_config'
require 'openc3/utilities/store'
require 'openc3/utilities/questdb_client'
require 'openc3/script/storage'

module OpenC3
  describe TlsConfig do
    TLS_ENV_KEYS = %w[
      OPENC3_REDIS_TLS OPENC3_REDIS_TLS_CA_FILE OPENC3_REDIS_TLS_CERT_FILE OPENC3_REDIS_TLS_KEY_FILE
      OPENC3_TSDB_TLS OPENC3_TSDB_TLS_CA_FILE OPENC3_BUCKET_TLS OPENC3_BUCKET_TLS_CA_FILE
      OPENC3_BUCKET_URL OPENC3_DEVEL OPENC3_REDIS_HOSTNAME OPENC3_REDIS_PORT
      OPENC3_REDIS_EPHEMERAL_HOSTNAME OPENC3_REDIS_EPHEMERAL_PORT
      OPENC3_TSDB_HOSTNAME OPENC3_TSDB_QUERY_PORT OPENC3_TSDB_USERNAME OPENC3_TSDB_PASSWORD
    ]

    around(:each) do |example|
      saved = TLS_ENV_KEYS.to_h { |key| [key, ENV[key]] }
      TLS_ENV_KEYS.each { |key| ENV.delete(key) }
      begin
        example.run
      ensure
        saved.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
      end
    end

    describe "Redis" do
      before(:each) do
        ENV['OPENC3_REDIS_HOSTNAME'] = 'openc3-redis'
        ENV['OPENC3_REDIS_PORT'] = '6379'
        ENV['OPENC3_REDIS_EPHEMERAL_HOSTNAME'] = 'openc3-redis-ephemeral'
        ENV['OPENC3_REDIS_EPHEMERAL_PORT'] = '6380'
      end

      it "defaults to plaintext redis:// with no ssl options" do
        expect(TlsConfig.redis_url('openc3-redis', 6379)).to eql 'redis://openc3-redis:6379'
        expect(TlsConfig.redis_ssl_params).to be_nil
        expect(TlsConfig.redis_options).to eql({})
      end

      it "switches to rediss:// with peer verification when OPENC3_REDIS_TLS is set" do
        ENV['OPENC3_REDIS_TLS'] = '1'
        expect(TlsConfig.redis_url('openc3-redis', 6379)).to eql 'rediss://openc3-redis:6379'
        options = TlsConfig.redis_options
        expect(options[:ssl]).to be true
        expect(options[:ssl_params]).to eql({ verify_mode: OpenSSL::SSL::VERIFY_PEER })
      end

      it "passes the CA file and client certificate when configured" do
        ENV['OPENC3_REDIS_TLS'] = 'true'
        ENV['OPENC3_REDIS_TLS_CA_FILE'] = '/certs/ca.pem'
        ENV['OPENC3_REDIS_TLS_CERT_FILE'] = '/certs/client.pem'
        ENV['OPENC3_REDIS_TLS_KEY_FILE'] = '/certs/client.key'
        expected = {
          verify_mode: OpenSSL::SSL::VERIFY_PEER,
          ca_file: '/certs/ca.pem',
          cert: '/certs/client.pem',
          key: '/certs/client.key'
        }
        expect(TlsConfig.redis_ssl_params).to eql expected
      end

      it "requires the client certificate and key together" do
        ENV['OPENC3_REDIS_TLS'] = '1'
        ENV['OPENC3_REDIS_TLS_CERT_FILE'] = '/certs/client.pem'
        expect { TlsConfig.redis_ssl_params }.to raise_error(TlsConfig::Error, /must be set together/)
      end

      it "builds Store connections over rediss:// with ssl_params" do
        ENV['OPENC3_REDIS_TLS'] = '1'
        ENV['OPENC3_REDIS_TLS_CA_FILE'] = '/certs/ca.pem'
        redis = double("Redis")
        expect(Redis).to receive(:new).with(
          url: 'rediss://openc3-redis:6379',
          username: ENV['OPENC3_REDIS_USERNAME'],
          password: ENV['OPENC3_REDIS_PASSWORD'],
          ssl: true,
          ssl_params: { verify_mode: OpenSSL::SSL::VERIFY_PEER, ca_file: '/certs/ca.pem' }
        ).and_return(redis)
        expect(Store.new.build_redis).to be redis
      end

      it "builds EphemeralStore connections over rediss://" do
        ENV['OPENC3_REDIS_TLS'] = '1'
        redis = double("Redis")
        expect(Redis).to receive(:new).with(hash_including(url: 'rediss://openc3-redis-ephemeral:6380', ssl: true)).and_return(redis)
        expect(EphemeralStore.new.build_redis).to be redis
      end

      it "keeps the plaintext Store connection when TLS is not enabled" do
        redis = double("Redis")
        expect(Redis).to receive(:new).with(
          url: 'redis://openc3-redis:6379',
          username: ENV['OPENC3_REDIS_USERNAME'],
          password: ENV['OPENC3_REDIS_PASSWORD']
        ).and_return(redis)
        expect(Store.new.build_redis).to be redis
      end
    end

    describe "QuestDB" do
      before(:each) do
        ENV['OPENC3_TSDB_HOSTNAME'] = 'openc3-tsdb'
        ENV['OPENC3_TSDB_QUERY_PORT'] = '8812'
        ENV['OPENC3_TSDB_USERNAME'] = 'quest'
        ENV['OPENC3_TSDB_PASSWORD'] = 'password'
      end

      it "adds no PG ssl parameters by default" do
        expect(TlsConfig.tsdb_pg_params).to eql({})
      end

      it "uses sslmode=verify-full with the system trust store when OPENC3_TSDB_TLS is set" do
        ENV['OPENC3_TSDB_TLS'] = '1'
        expect(TlsConfig.tsdb_pg_params).to eql({ sslmode: 'verify-full', sslrootcert: 'system' })
      end

      it "uses the configured CA file as sslrootcert" do
        ENV['OPENC3_TSDB_TLS'] = '1'
        ENV['OPENC3_TSDB_TLS_CA_FILE'] = '/certs/tsdb-ca.pem'
        expect(TlsConfig.tsdb_pg_params).to eql({ sslmode: 'verify-full', sslrootcert: '/certs/tsdb-ca.pem' })
      end

      it "passes the ssl parameters to PG::Connection" do
        ENV['OPENC3_TSDB_TLS'] = '1'
        conn = double("PG::Connection", close: nil)
        expect(PG::Connection).to receive(:new).with(
          host: 'openc3-tsdb', port: '8812', user: 'quest', password: 'password', dbname: 'qdb',
          sslmode: 'verify-full', sslrootcert: 'system'
        ).and_return(conn)
        expect(QuestDBClient.check_connection).to be true
      end
    end

    describe "Buckets" do
      it "defaults to the in-cluster plaintext endpoint when nothing is configured" do
        expect(TlsConfig.bucket_endpoint).to eql 'http://openc3-buckets:9000'
        expect(TlsConfig.bucket_endpoint(devel: true)).to eql 'http://127.0.0.1:9000'
      end

      it "uses OPENC3_BUCKET_URL when set" do
        ENV['OPENC3_BUCKET_URL'] = 'http://buckets.example:9000'
        expect(TlsConfig.bucket_endpoint).to eql 'http://buckets.example:9000'
      end

      it "defaults to https when OPENC3_BUCKET_TLS is set" do
        ENV['OPENC3_BUCKET_TLS'] = '1'
        expect(TlsConfig.bucket_endpoint).to eql 'https://openc3-buckets:9000'
        expect(TlsConfig.bucket_endpoint(devel: true)).to eql 'https://127.0.0.1:9000'
      end

      it "accepts an https OPENC3_BUCKET_URL when OPENC3_BUCKET_TLS is set" do
        ENV['OPENC3_BUCKET_TLS'] = '1'
        ENV['OPENC3_BUCKET_URL'] = 'HTTPS://buckets.example:9000'
        expect(TlsConfig.bucket_endpoint).to eql 'HTTPS://buckets.example:9000'
      end

      it "fails closed on a plaintext OPENC3_BUCKET_URL when OPENC3_BUCKET_TLS is set" do
        ENV['OPENC3_BUCKET_TLS'] = '1'
        ENV['OPENC3_BUCKET_URL'] = 'http://openc3-buckets:9000'
        expect { TlsConfig.bucket_endpoint }.to raise_error(TlsConfig::Error, /is not https/)
      end

      it "exposes the bucket CA file" do
        expect(TlsConfig.bucket_ca_file).to be_nil
        ENV['OPENC3_BUCKET_TLS_CA_FILE'] = '/certs/bucket-ca.pem'
        expect(TlsConfig.bucket_ca_file).to eql '/certs/bucket-ca.pem'
      end

      context "Script storage" do
        let(:script) { Object.new.extend(OpenC3::Script) }

        before(:each) do
          @saved_in_cluster = $openc3_in_cluster
          $openc3_in_cluster = true
          ENV['OPENC3_CLOUD'] = 'local'
        end

        after(:each) do
          $openc3_in_cluster = @saved_in_cluster
        end

        it "builds presigned URLs against the https bucket endpoint" do
          ENV['OPENC3_BUCKET_TLS'] = '1'
          uri = script.send(:_get_uri, '/config/DEFAULT/targets/INST/file.rb?sig=1')
          expect(uri.to_s).to eql 'https://openc3-buckets:9000/config/DEFAULT/targets/INST/file.rb?sig=1'
          expect(uri.scheme).to eql 'https'
        end

        it "rejects a plaintext bucket URL when TLS is required" do
          ENV['OPENC3_BUCKET_TLS'] = '1'
          ENV['OPENC3_BUCKET_URL'] = 'http://openc3-buckets:9000'
          expect { script.send(:_get_uri, '/config/file') }.to raise_error(TlsConfig::Error)
        end

        it "enables TLS with the bucket CA file for https URLs" do
          ENV['OPENC3_BUCKET_TLS_CA_FILE'] = '/certs/bucket-ca.pem'
          options = script.send(:_http_options, URI.parse('https://openc3-buckets:9000/x'))
          expect(options).to eql({ use_ssl: true, ca_file: '/certs/bucket-ca.pem' })
          options = script.send(:_http_options, URI.parse('http://openc3-buckets:9000/x'))
          expect(options).to eql({ use_ssl: false })
        end
      end
    end
  end
end

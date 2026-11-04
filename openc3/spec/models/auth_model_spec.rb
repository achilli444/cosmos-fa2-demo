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
require 'tempfile'
require 'spec_helper'
require 'openc3/models/auth_model'

module OpenC3
  PW_HASH_PRIMARY_KEY = 'OPENC3__TOKEN'
  AUTH_INITIAL_PASSWORD = ENV['OPENC3_API_PASSWORD']
  AUTH_NEW_PASSWORD = 'Unit-Test!Credential-2027'

  describe AuthModel, type: :model do
    before(:each) do
      @redis = mock_redis()

      # Disable the auth model mock for this spec
      allow(OpenC3::AuthModel).to receive(:verify).and_call_original
      allow(OpenC3::AuthModel).to receive(:verify_no_service).and_call_original
    end

    describe "authentication" do
      it "creates new" do
        model = AuthModel.new()
        expect(model).to be_a(AuthModel)
      end

      it "self.set" do
        expect{ AuthModel.set(AUTH_NEW_PASSWORD, nil) }.to \
          raise_error(/old_password must not be nil or empty/)

        expect{ AuthModel.set(AUTH_NEW_PASSWORD, 'Wrong-Old!Credential-1', PW_HASH_PRIMARY_KEY) }.to \
          raise_error(/old_password incorrect/)

        AuthModel.set(AUTH_NEW_PASSWORD, AUTH_INITIAL_PASSWORD)
        expect(AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any)).to eq(false)
        expect(AuthModel.verify_no_service(AUTH_NEW_PASSWORD, mode: :any)).to eq(true)
      end

      describe "password policy" do
        # IA-5(1): minimum length, composition, common/compromised password
        # blocklist, and no reuse of the current password. Every rejection is a
        # PasswordPolicyError so callers can answer with a validation error.
        it "rejects empty passwords" do
          expect { AuthModel.set(nil, AUTH_INITIAL_PASSWORD) }.to \
            raise_error(AuthModel::PasswordPolicyError, /must not be nil or empty/)
          expect { AuthModel.set('', AUTH_INITIAL_PASSWORD) }.to \
            raise_error(AuthModel::PasswordPolicyError, /must not be nil or empty/)
        end

        it "requires at least 15 characters by default" do
          expect(AuthModel.min_password_length).to eq(15)
          expect { AuthModel.set('Short!Cred-14c', AUTH_INITIAL_PASSWORD) }.to \
            raise_error(AuthModel::PasswordPolicyError, /at least 15 characters/)
          AuthModel.set('Short!Cred-15ch', AUTH_INITIAL_PASSWORD)
          expect(AuthModel.verify_no_service('Short!Cred-15ch', mode: :password)).to eq(true)
        end

        it "lets OPENC3_MIN_PASSWORD_LENGTH raise but not lower the minimum" do
          allow(ENV).to receive(:fetch).and_call_original
          allow(ENV).to receive(:fetch).with('OPENC3_MIN_PASSWORD_LENGTH', '').and_return('20')
          expect(AuthModel.min_password_length).to eq(20)
          expect { AuthModel.set('Short!Cred-15ch', AUTH_INITIAL_PASSWORD) }.to \
            raise_error(AuthModel::PasswordPolicyError, /at least 20 characters/)

          allow(ENV).to receive(:fetch).with('OPENC3_MIN_PASSWORD_LENGTH', '').and_return('8')
          expect(AuthModel.min_password_length).to eq(15)
          allow(ENV).to receive(:fetch).with('OPENC3_MIN_PASSWORD_LENGTH', '').and_return('bogus')
          expect(AuthModel.min_password_length).to eq(15)
        end

        it "requires upper, lower, digit and symbol characters" do
          ['alllowercase-2026!!', 'ALLUPPERCASE-2026!!', 'NoDigitsInHere-!!!', 'NoSymbolsInHere2026'].each do |pw|
            expect { AuthModel.set(pw, AUTH_INITIAL_PASSWORD) }.to \
              raise_error(AuthModel::PasswordPolicyError, /upper and lower case letters, a number, and a symbol/), pw
          end
        end

        it "rejects passwords that are or contain a commonly used password" do
          # 'password' and 'qwertyuiop' are in the bundled list; 'openc3' is an expected term
          ['Password12345!!', 'xxQWERTYUIOPxx-1!', 'My-Openc3-Secret-1!', 'CosmosOperator-2026!'].each do |pw|
            expect { AuthModel.set(pw, AUTH_INITIAL_PASSWORD) }.to \
              raise_error(AuthModel::PasswordPolicyError, /commonly used password/), pw
          end
          # Short list entries only match the whole password, so a word like
          # 'love' inside a long passphrase is fine
          AuthModel.set('Love-The-Mission-2026!', AUTH_INITIAL_PASSWORD)
        end

        it "rejects entries from an operator supplied blocklist file" do
          Tempfile.create('blocklist') do |file|
            file.puts '# site specific'
            file.puts 'MissionControl'
            file.puts 'xyzzy'
            file.flush
            allow(ENV).to receive(:fetch).and_call_original
            allow(ENV).to receive(:fetch).with('OPENC3_PASSWORD_BLOCKLIST_FILE', nil).and_return(file.path)
            expect { AuthModel.set('MissionControl-2026!', AUTH_INITIAL_PASSWORD) }.to \
              raise_error(AuthModel::PasswordPolicyError, /commonly used password/)
            # 5 characters is below the substring threshold: whole-match only
            AuthModel.set('Xyzzy-Is-Fine-2026!', AUTH_INITIAL_PASSWORD)
          end
        end

        it "rejects reusing the current password" do
          expect { AuthModel.set(AUTH_INITIAL_PASSWORD, AUTH_INITIAL_PASSWORD) }.to \
            raise_error(AuthModel::PasswordPolicyError, /different from the current password/)
          expect(AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :password)).to eq(true)
        end

        it "checks policy before touching the stored password" do
          expect(Store).not_to receive(:set)
          expect { AuthModel.set('weak', AUTH_INITIAL_PASSWORD) }.to raise_error(AuthModel::PasswordPolicyError)
        end
      end

      it "self.verify" do
        expect(AuthModel.verify('badpassword')).to eq(false)
        expect(AuthModel.verify(AUTH_INITIAL_PASSWORD, no_password: false)).to eq(true)
        expect(AuthModel.verify(AUTH_INITIAL_PASSWORD, no_password: true)).to eq(false)
      end

      it "verifies and terminates a session token" do
        token1 = AuthModel.generate_session
        token2 = AuthModel.generate_session
        expect(AuthModel.verify(token1)).to eq(true)
        expect(AuthModel.verify(token2)).to eq(true)

        # Make sure terminating one doesn't affect the other
        AuthModel.terminate(token1)
        expect(AuthModel.verify(token1)).to eq(false)
        expect(AuthModel.verify(token2)).to eq(true)
      end

      it "verifies a session token and logs out" do
        token1 = AuthModel.generate_session
        token2 = AuthModel.generate_session
        expect(AuthModel.verify(token1)).to eq(true)
        expect(AuthModel.verify(token2)).to eq(true)

        # Make sure all sessions are terminated
        AuthModel.logout
        expect(AuthModel.verify(token1)).to eq(false)
        expect(AuthModel.verify(token2)).to eq(false)
      end

      it "creates a one-time use token" do
        token = AuthModel.generate_session(otp: true)
        expect(AuthModel.verify(token)).to eq(true)

        # Already verified, second attempt shouldn't work
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "revokes all sessions on password change" do
        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true)

        AuthModel.set(AUTH_NEW_PASSWORD, AUTH_INITIAL_PASSWORD)
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "verifies a brand new session token immediately after a failed check" do
        # This is the login page sequence: the stale token in localStorage is
        # checked (fails), the user types the password, and the token that comes
        # back is checked on the next page load. A cached negative result would
        # 401 that check and bounce the user straight back to the login form.
        stale = "#{AuthModel::SESSION_PREFIX}#{'A' * 22}"
        expect(AuthModel.verify(stale)).to eq(false)

        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true)
        expect(AuthModel.verify(stale)).to eq(false)
      end

      it "never reads the entire session hash" do
        # verify_token is unauthenticated, so a caller must not be able to make
        # us pull every session ever created on every request. Nothing prunes
        # the sessions hash short of a logout, so it only grows.
        expect(Store).not_to receive(:hgetall)

        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true) # reads just this token
        expect(AuthModel.verify(token)).to eq(true) # served from the cache
        10.times do
          bogus = "#{AuthModel::SESSION_PREFIX}#{SecureRandom.urlsafe_base64(nil, false)}"
          expect(AuthModel.verify(bogus)).to eq(false)
        end
      end

      it "stops using a cached session token once the cache expires" do
        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true)

        # Delete it behind the cache's back, the way another process would
        @redis.hdel(AuthModel::SESSIONS_KEY, token)
        expect(AuthModel.verify(token)).to eq(true)

        # Past SESSION_CACHE_TIMEOUT the cache is dropped and the token is gone.
        # Compute the future time before stubbing so Time.now isn't stubbed yet.
        future = Time.now + AuthModel::SESSION_CACHE_TIMEOUT + 1
        allow(Time).to receive(:now).and_return(future)
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "raises when stored password hash is SHA256" do
        @redis.set(PW_HASH_PRIMARY_KEY, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end
  end
end

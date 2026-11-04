# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.

require 'spec_helper'
require 'openc3/models/bridge_model'

module OpenC3
  describe BridgeModel do
    before(:each) do
      mock_redis()
    end

    describe "generate_enrollment_token" do
      it "stores only a hash of the one-time enrollment code with its timestamp" do
        now = Time.at(1_700_000_000).utc
        model = BridgeModel.new(name: "LAB1", scope: "DEFAULT", ticket: "ticket")
        model.create

        allow(Time).to receive(:now).and_return(now)
        token = model.generate_enrollment_token

        stored = BridgeModel.get(name: "LAB1", scope: "DEFAULT")
        payload = JSON.parse(Base64.urlsafe_decode64(token))
        expect(payload["code"]).to match(/\A[0-9a-f]{32}\z/)
        expect(stored["enroll_code_generated_at"]).to eq(now.to_i)
        expect(stored["enroll_code_hash"]).to eq(Digest::SHA256.hexdigest(payload["code"]))
        expect(stored).not_to have_key("enroll_code")
        expect(JSON.generate(stored)).not_to include(payload["code"])
        expect(JSON.generate(model.as_json)).not_to include(payload["code"])
      end

      it "requires a ticket" do
        model = BridgeModel.new(name: "LAB1", scope: "DEFAULT")
        expect { model.generate_enrollment_token }.to raise_error(/no ticket yet/)
      end
    end

    describe "enrollment_code_valid?" do
      it "accepts the code only within the TTL" do
        model = BridgeModel.new(
          name: "LAB1",
          scope: "DEFAULT",
          enroll_code_hash: BridgeModel.hash_enrollment_code("one-time-code"),
          enroll_code_generated_at: 1_000
        )
        expect(model.enrollment_code_valid?("one-time-code", 1_000)).to be true
        expect(model.enrollment_code_valid?("one-time-code", 1_000 + BridgeModel::ENROLLMENT_CODE_TTL_SECONDS)).to be true
        expect(model.enrollment_code_valid?("one-time-code", 1_001 + BridgeModel::ENROLLMENT_CODE_TTL_SECONDS)).to be false
        expect(model.enrollment_code_valid?("wrong-code", 1_001)).to be false
        expect(model.enrollment_code_valid?(nil, 1_001)).to be false
      end

      it "fails closed for legacy plaintext enroll_code records and discards the plaintext" do
        json = { 'name' => 'LAB1', 'scope' => 'DEFAULT', 'enroll_code' => 'legacy-code', 'enroll_code_generated_at' => 1_000 }
        model = BridgeModel.from_json(json, scope: 'DEFAULT')
        expect(model.enrollment_code_valid?("legacy-code", 1_000)).to be false
        expect(model.as_json).not_to have_key("enroll_code")
        expect(JSON.generate(model.as_json)).not_to include("legacy-code")
      end

      it "clears the pending code" do
        model = BridgeModel.new(
          name: "LAB1",
          scope: "DEFAULT",
          enroll_code_hash: BridgeModel.hash_enrollment_code("one-time-code"),
          enroll_code_generated_at: 1_000
        )
        model.clear_enrollment_code
        expect(model.enroll_code_hash).to be_nil
        expect(model.enroll_code_generated_at).to be_nil
        expect(model.enrollment_code_valid?("one-time-code", 1_000)).to be false
      end
    end
  end
end

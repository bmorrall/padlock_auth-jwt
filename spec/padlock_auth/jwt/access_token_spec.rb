require "rails_helper"

RSpec.describe PadlockAuth::Jwt::AccessToken do
  subject { described_class.new(raw_token, strategy) }

  let(:secret_key) { "my$ecretK3y" }
  let(:algorithm) { "HS256" }

  let(:strategy) do
    # Worlds most permissive strategy
    instance_double(
      PadlockAuth::Jwt::Strategy,
      secret_key: secret_key,
      algorithm: algorithm,
      exp_required?: false,
      nbf_required?: false,
      iss_required?: false,
      aud_required?: false,
      jti_required?: false,
      iat_required?: false,
      sub_required?: false,
      expiry_leeway: 0,
      not_before_leeway: 0,
      issuers: [],
      verify_jti: proc { true },
      header_types: PadlockAuth::Jwt::Strategy::REQUIRED_HEADER_TYPES,
      subject: []
    )
  end

  def encode_access_token(key = secret_key, **payload)
    JWT.encode(payload, key, algorithm, {typ: "at+jwt"})
  end

  context "with a simple access token" do
    let(:raw_token) { encode_access_token }

    it { expect(subject.acceptable?([])).to be true }

    it { expect(subject.accessible?).to be true }

    it { expect(subject.invalid_token_reason).to eq :unknown }

    it { expect(subject.header).to eq("alg" => algorithm, "typ" => "at+jwt") }
    it { expect(subject.payload).to eq({}) }
  end

  context "with a simple access token with a custom payload" do
    let(:raw_token) { encode_access_token(user_name: "Jane Tester", user_email: "jane@example.com") }

    it { expect(subject.accessible?).to be true }

    it { expect(subject.payload).to eq("user_name" => "Jane Tester", "user_email" => "jane@example.com") }
  end

  # Token Validation

  context "with a non-JWT token" do
    let(:raw_token) { "not a jwt token" }

    it { expect(subject.accessible?).to be false }

    it { expect(subject.includes_scope?([])).to be false }
    it { expect(subject.includes_scope?(["valid"])).to be false }

    it { expect(subject.invalid_token_reason).to eq(:invalid_jwt_token) }
    it { expect(subject.forbidden_token_reason).to eq(:invalid_jwt_token) }

    it { expect(subject.header).to be_nil }
    it { expect(subject.payload).to be_nil }
  end

  # Signature Validation

  [
    "HS256", # HMAC using SHA-256 hash algorithm
    "HS384", # HMAC using SHA-384 hash algorithm
    "HS512" # HMAC using SHA-512 hash algorithm
  ].each do |algorithm|
    context "with a valid access token signed with #{algorithm}" do
      let(:algorithm) { algorithm }
      let(:raw_token) { encode_access_token }

      it { expect(subject.accessible?).to be true }

      it "rejects tokens signed with a different secret key" do
        access_token = described_class.new(encode_access_token("invalid"), strategy)
        expect(access_token.accessible?).to be false
        expect(access_token.invalid_token_reason).to eq(:invalid_signature)
      end
    end
  end

  [
    "RS256", # RSA using SHA-256 hash algorithm
    "RS384", # RSA using SHA-384 hash algorithm
    "RS512", # RSA using SHA-512 hash algorithm
    "PS256", # RSASSA-PSS using SHA-256 hash algorithm
    "PS384", # RSASSA-PSS using SHA-384 hash algorithm
    "PS512" # RSASSA-PSS using SHA-512 hash algorithm
  ].each do |algorithm|
    context "with a valid access token signed with #{algorithm}" do
      let(:rsa_private) { OpenSSL::PKey::RSA.generate(2048) }

      let(:raw_token) { encode_access_token(rsa_private) }
      let(:secret_key) { rsa_private.public_key }
      let(:algorithm) { algorithm }

      it { expect(subject.accessible?).to be true }

      it "rejects tokens signed with a different RSA key" do
        access_token = described_class.new(encode_access_token(OpenSSL::PKey::RSA.generate(2048)), strategy)
        expect(access_token.accessible?).to be false
        expect(access_token.invalid_token_reason).to eq(:invalid_signature)
      end
    end
  end

  {
    "ES256" => "prime256v1", # ECDSA using P-256 and SHA-256
    "ES384" => "secp384r1", # ECDSA using P-384 and SHA-384
    "ES512" => "secp521r1", # ECDSA using P-521 and SHA-512
    "ES256K" => "secp256k1" # ECDSA using P-256K and SHA-256
  }.each do |algorithm, ec_group|
    context "with a valid access token signed with #{algorithm}" do
      let(:ecdsa_key) { OpenSSL::PKey::EC.generate(ec_group) }

      let(:raw_token) { encode_access_token }
      let(:secret_key) { ecdsa_key }
      let(:algorithm) { algorithm }

      it { expect(subject.accessible?).to be true }

      it "rejects tokens signed with a different ec group" do
        access_token = described_class.new(encode_access_token(OpenSSL::PKey::EC.generate(ec_group)), strategy)
        expect(access_token.accessible?).to be false
        expect(access_token.invalid_token_reason).to eq(:invalid_signature)
      end
    end
  end

  context "with a valid access token signed with ED25519" do
    let(:private_key) { Ed25519::SigningKey.new("abcdefghijklmnopqrstuvwxyzABCDEF") }

    let(:raw_token) { encode_access_token(private_key) }
    let(:secret_key) { private_key.verify_key }
    let(:algorithm) { "ED25519" }

    before { require "jwt/eddsa" }

    it { expect(subject.accessible?).to be true }

    it { expect(subject.header).to eq("alg" => "EdDSA", "typ" => "at+jwt") }

    it "rejects tokens signed with a different ED25519 key" do
      other_private_key = Ed25519::SigningKey.new("abcdefghijklmnopqrstuvwxyzABCDEF".reverse)
      access_token = described_class.new(encode_access_token(other_private_key), strategy)
      expect(access_token.accessible?).to be false
      expect(access_token.invalid_token_reason).to eq(:invalid_signature)
    end
  end

  # claims validation

  context "with a token missing a required exp claim" do
    let(:raw_token) { encode_access_token }

    before { allow(strategy).to receive(:exp_required?).and_return(true) }

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:missing_exp_claim) }
  end

  context "with a token missing a required nbf claim" do
    let(:raw_token) { encode_access_token }

    before { allow(strategy).to receive(:nbf_required?).and_return(true) }

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:missing_nbf_claim) }
  end

  context "with a token missing a required iat claim" do
    let(:raw_token) { encode_access_token }

    before { allow(strategy).to receive(:iat_required?).and_return(true) }

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:missing_iat_claim) }
  end

  context "with a token missing a required iss claim" do
    let(:raw_token) { encode_access_token }

    before { allow(strategy).to receive(:iss_required?).and_return(true) }

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:missing_iss_claim) }
  end

  context "with a token missing a required aud claim" do
    let(:raw_token) { encode_access_token }

    before { allow(strategy).to receive(:aud_required?).and_return(true) }

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:missing_aud_claim) }
  end

  context "with a token missing a required jti claim" do
    let(:raw_token) { encode_access_token }

    before { allow(strategy).to receive(:jti_required?).and_return(true) }

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:missing_jti_claim) }
  end

  context "with a token missing a required sub claim" do
    let(:raw_token) { encode_access_token }

    before { allow(strategy).to receive(:sub_required?).and_return(true) }

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:missing_sub_claim) }
  end

  # "exp" (Expiration Time) Claim

  context "with an expired access token" do
    let(:expiry_time) { 1.second.ago.to_i }
    let(:raw_token) { encode_access_token(exp: expiry_time) }

    before do
      allow(strategy).to receive(:expiry_leeway).and_return(0)
    end

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:invalid_exp_claim) }

    it { expect(subject.payload["exp"]).to eq(expiry_time) }
  end

  context "with an expired access token within leeway" do
    let(:raw_token) { encode_access_token(exp: 1.second.ago.to_i) }

    before do
      allow(strategy).to receive(:expiry_leeway).and_return(2)
    end

    it { expect(subject.accessible?).to be true }
  end

  # "nbf" (Not Before) Claim

  context "with a token that is not yet valid" do
    let(:not_before) { 1.second.from_now.to_i }
    let(:raw_token) { encode_access_token(nbf: not_before) }

    before do
      allow(strategy).to receive(:not_before_leeway).and_return(0)
    end

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:invalid_nbf_claim) }

    it { expect(subject.payload["nbf"]).to eq(not_before) }
  end

  context "with a token that is not yet valid within leeway" do
    let(:raw_token) { encode_access_token(nbf: 1.second.from_now.to_i) }

    before do
      allow(strategy).to receive(:not_before_leeway).and_return(2)
    end

    it { expect(subject.accessible?).to be true }
  end

  # "iss" (Issuer) Claim

  context "with a valid issuer access token" do
    let(:raw_token) { encode_access_token(iss: "valid") }

    before do
      allow(strategy).to receive(:issuers).and_return(["valid"])
    end

    it { expect(subject.accessible?).to be true }

    it { expect(subject.payload["iss"]).to eq("valid") }
  end

  context "with an invalid issuer access token" do
    let(:raw_token) { encode_access_token(iss: "invalid") }

    before do
      allow(strategy).to receive(:issuers).and_return(["valid"])
    end

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:invalid_iss_claim) }
  end

  # "aud" (Audience) Claim

  context "with a token with a single aud claim" do
    let(:raw_token) { encode_access_token(aud: "valid") }

    it { expect(subject.acceptable?([])).to be true }
    it { expect(subject.acceptable?(["valid"])).to be true }
    it { expect(subject.acceptable?([:valid])).to be true }
    it { expect(subject.acceptable?(PadlockAuth::Config::Scopes.from_array(["valid"]))).to be true }
    it { expect(subject.acceptable?(["invalid"])).to be false }

    it { expect(subject.accessible?).to be true }

    it { expect(subject.includes_scope?([])).to be true }
    it { expect(subject.includes_scope?(["valid"])).to be true }
    it { expect(subject.includes_scope?(["invalid"])).to be false }
    it { expect(subject.includes_scope?(["valid", "invalid"])).to be true } # at least one valid

    it { expect(subject.forbidden_token_reason).to eq(:invalid_aud_claim) }

    it { expect(subject.payload["aud"]).to eq("valid") }
  end

  context "with a token with multiple aud claims" do
    let(:raw_token) { encode_access_token(aud: ["valid1", "valid2"]) }

    it { expect(subject.acceptable?([])).to be true }
    it { expect(subject.acceptable?(["valid1"])).to be true }
    it { expect(subject.acceptable?(["valid2"])).to be true }
    it { expect(subject.acceptable?(["invalid"])).to be false }
    it { expect(subject.acceptable?(["valid1", "valid2"])).to be true }
    it { expect(subject.acceptable?(["valid1", "valid2", "invalid"])).to be true }

    it { expect(subject.payload["aud"]).to eq(["valid1", "valid2"]) }
  end

  context "with a token without an aud claim" do
    let(:raw_token) { encode_access_token }

    it { expect(subject.acceptable?([])).to be true }
    it { expect(subject.acceptable?(["valid"])).to be false }

    it { expect(subject.accessible?).to be true }

    it { expect(subject.includes_scope?([])).to be true }
    it { expect(subject.includes_scope?(["valid"])).to be false }

    it { expect(subject.forbidden_token_reason).to eq(:invalid_aud_claim) }
  end

  # "jti" (JWT ID) Claim

  context "with a valid jti access token" do
    let(:raw_token) { encode_access_token(jti: "valid") }

    before do
      allow(strategy).to receive(:verify_jti).and_return(proc { |jti| jti == "valid" })
    end

    it { expect(subject.accessible?).to be true }

    it { expect(subject.payload["jti"]).to eq("valid") }
  end

  context "with an invalid jti access token" do
    let(:raw_token) { encode_access_token(jti: "invalid") }

    before do
      allow(strategy).to receive(:verify_jti).and_return(proc { |jti| jti == "valid" })
    end

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:invalid_jti_claim) }
  end

  # "sub" (Subject) Claim

  context "with a valid subject access token" do
    let(:raw_token) { encode_access_token(sub: "PadlockAuth") }

    before do
      allow(strategy).to receive(:subject).and_return("PadlockAuth")
    end

    it { expect(subject.accessible?).to be true }

    it { expect(subject.payload["sub"]).to eq("PadlockAuth") }
  end

  context "with an invalid subject access token" do
    let(:raw_token) { encode_access_token(sub: "Invalid") }

    before do
      allow(strategy).to receive(:sub_required?).and_return(true)
      allow(strategy).to receive(:subject).and_return(["PadlockAuth"])
    end

    it { expect(subject.accessible?).to be false }

    it { expect(subject.invalid_token_reason).to eq(:invalid_sub_claim) }
  end

  context "with no defined subject and a provided sub claim" do
    let(:raw_token) { encode_access_token(sub: "AuthSubject") }

    before do
      allow(strategy).to receive(:sub_required?).and_return(false)
      allow(strategy).to receive(:subject).and_return(nil)
    end

    it { expect(subject.accessible?).to be true }
  end
end

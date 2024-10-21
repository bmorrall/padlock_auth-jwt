require "rails_helper"

RSpec.describe PadlockAuth::Jwt::Strategy do
  subject(:strategy) { build_strategy }

  def build_strategy(**options)
    described_class.build do
      secret_key "my$ecretK3y"
      algorithm "HS256"

      options.each do |key, value|
        public_send(key, value)
      end
    end
  end

  describe ".build" do
    it "returns a new instance of the strategy" do
      instance = described_class.build do
        secret_key "my$ecretK3y"
        algorithm "HS256"
      end
      expect(instance).to be_a(described_class)
    end

    it "raises an error if no secret_key is provided" do
      expect do
        described_class.build do
          algorithm "HS256"
        end
      end.to raise_error(ArgumentError, "secret_key is required")
    end

    it "raises an error if no algorithm is provided" do
      expect do
        described_class.build do
          secret_key "my$ecretK3y"
          algorithm nil
        end
      end.to raise_error(ArgumentError, "algorithm is required")
    end

    it "defaults to a RS256 allgorithm" do
      strategy = described_class.build do
        secret_key "my$ecretK3y"
      end
      expect(strategy.algorithm).to eq("RS256")
    end

    it "raises an error if header_types is set to an empty array" do
      expect do
        build_strategy(header_types: [])
      end.to raise_error(ArgumentError, "header_types cannot be empty")
    end
  end

  describe "#build_access_token" do
    it "returns a new instance of a jwt access token" do
      expect(PadlockAuth::Jwt::AccessToken).to receive(:new).with("token", strategy).and_call_original
      expect(strategy.build_access_token("token")).to be_a(PadlockAuth::Jwt::AccessToken)
    end
  end

  describe "#validate!" do
    it "returns true when the strategy is valid" do
      strategy = build_strategy
      expect(strategy.validate!).to eq(true)
    end
  end

  # Signature

  describe "#secret_key" do
    it "returns the secret key" do
      strategy = build_strategy(secret_key: "Top$ecret")
      expect(strategy.secret_key).to eq("Top$ecret")
    end
  end

  describe "#algorithm" do
    it "returns the algorithm" do
      strategy = build_strategy(algorithm: "HS512")
      expect(strategy.algorithm).to eq("HS512")
    end
  end

  # "exp" (Expiration Time) Claim

  describe "#exp_required?" do
    it "is true by default" do
      expect(build_strategy.exp_required?).to be true
    end

    it "returns true when set to true" do
      strategy = build_strategy(require_exp: true)
      expect(strategy.exp_required?).to eq true
    end

    it "returns false when set to false" do
      strategy = build_strategy(require_exp: false)
      expect(strategy.exp_required?).to eq false
    end
  end

  describe "#expiry_leeway" do
    it "returns 0 by default" do
      expect(strategy.expiry_leeway).to eq(0)
    end

    it "returns the leeway when set" do
      strategy = build_strategy(expiry_leeway: 10)
      expect(strategy.expiry_leeway).to eq(10)
    end
  end

  # "nbf" (Not Before) Claim

  describe "#nbf_required?" do
    it "is false by default" do
      expect(build_strategy.nbf_required?).to be false
    end

    it "returns true when set" do
      strategy = build_strategy(require_nbf: true)
      expect(strategy.nbf_required?).to eq true
    end
  end

  describe "#not_before_leeway" do
    it "returns 0 by default" do
      expect(strategy.not_before_leeway).to eq(0)
    end

    it "returns the leeway when set" do
      strategy = build_strategy(not_before_leeway: 10)
      expect(strategy.not_before_leeway).to eq(10)
    end

    it "aliases nbf_leeway to not_before_leeway" do
      strategy = build_strategy(nbf_leeway: 10)
      expect(strategy.not_before_leeway).to eq(10)
    end
  end

  # "iss" (Issuer) Claim

  describe "#iss_required?" do
    it "is false by default" do
      expect(build_strategy.iss_required?).to be false
    end

    it "returns true when set" do
      strategy = build_strategy(require_iss: true, issuers: "issuer")
      expect(strategy.iss_required?).to eq true
    end

    it "prevents setting issuer to false with a nil issuer" do
      expect do
        build_strategy(require_iss: true, issuers: nil)
      end.to raise_error(ArgumentError, "issuers are required when require_iss is true")
    end

    it "prevents setting issuer to false with an empty issuer" do
      expect do
        build_strategy(require_iss: true, issuers: [])
      end.to raise_error(ArgumentError, "issuers are required when require_iss is true")
    end
  end

  describe "#issuers" do
    it "returns an empty array by default" do
      expect(strategy.issuers).to eq([])
    end

    it "returns single issuers in an array" do
      strategy = build_strategy(issuers: "issuer")
      expect(strategy.issuers).to eq(["issuer"])
    end

    it "returns multiple issuers in an array" do
      strategy = build_strategy(issuers: ["issuer1", "issuer2"])
      expect(strategy.issuers).to eq(["issuer1", "issuer2"])
    end

    it "returns an empty array when issuers are nil" do
      strategy = build_strategy(issuers: nil)
      expect(strategy.issuers).to eq([])
    end
  end

  # "aud" (Audience) Claim

  describe "#aud_required?" do
    it "is true by default" do
      expect(build_strategy.aud_required?).to be true
    end

    it "returns true when set to true" do
      strategy = build_strategy(require_aud: true)
      expect(strategy.aud_required?).to eq true
    end

    it "returns false when set to false" do
      strategy = build_strategy(require_aud: false)
      expect(strategy.aud_required?).to eq false
    end
  end

  # "jti" (JWT ID) Claim

  describe "#jti_required?" do
    it "is true by default" do
      expect(build_strategy.jti_required?).to be true
    end

    it "returns true when set to true" do
      strategy = build_strategy(require_jti: true)
      expect(strategy.jti_required?).to eq true
    end

    it "returns false when set to false" do
      strategy = build_strategy(require_jti: false)
      expect(strategy.jti_required?).to eq false
    end
  end

  describe "#verify_jti" do
    it "returns a proc that always returns true by default" do
      expect(strategy.verify_jti.call("jti")).to eq(true)
    end

    it "evaluates the proc when set" do
      strategy = build_strategy(verify_jti: proc { |jti| jti == "jti" })
      expect(strategy.verify_jti.call("jti")).to eq(true)
      expect(strategy.verify_jti.call("invalid")).to eq(false)
    end
  end

  # "iat" (Issued At) Claim

  describe "#iat_required?" do
    it "is true by default" do
      expect(build_strategy.iat_required?).to be true
    end

    it "returns true when set to true" do
      strategy = build_strategy(require_iat: true)
      expect(strategy.iat_required?).to eq true
    end

    it "returns false when set to false" do
      strategy = build_strategy(require_iat: false)
      expect(strategy.iat_required?).to eq false
    end
  end

  # "sub" (Subject) Claim

  describe "#sub_required?" do
    it "is true by default" do
      expect(build_strategy.sub_required?).to be true
    end

    it "returns true when set to true with a required subject" do
      strategy = build_strategy(require_sub: true, subject: "subject")
      expect(strategy.sub_required?).to eq true
    end

    it "returns true when set to true without a required subject" do
      strategy = build_strategy(require_sub: true, subject: nil)
      expect(strategy.sub_required?).to eq true
    end

    it "returns false when set to false" do
      strategy = build_strategy(require_sub: false)
      expect(strategy.sub_required?).to eq false
    end

    it "prevents setting subject to a value when require sub is false" do
      expect do
        build_strategy(require_sub: false, subject: ["subject"])
      end.to raise_error(ArgumentError, "subject is not required")
    end
  end

  describe "#subject" do
    it "returns an array of subjects when set" do
      strategy = build_strategy(subject: "subject")
      expect(strategy.subject).to eq(["subject"])
    end

    it "returns an empty array by default" do
      strategy = build_strategy
      expect(strategy.subject).to eq []
    end

    it "returns an empty array when subject is nil" do
      strategy = build_strategy(subject: nil)
      expect(strategy.subject).to eq []
    end
  end
end

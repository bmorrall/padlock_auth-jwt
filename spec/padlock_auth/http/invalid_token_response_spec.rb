require "rails_helper"

RSpec.describe PadlockAuth::Jwt::Http::InvalidTokenResponse do
  context "with an invalid_signature invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :invalid_signature)) }

    it { expect(response.reason).to eq(:invalid_signature) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises an InvalidSignature error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::InvalidSignature)
        expect(error.message).to eq("The access token has an invalid signature.")
      end
    end
  end

  context "with a missing_exp_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :missing_exp_claim)) }

    it { expect(response.reason).to eq(:missing_exp_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises a MissingRequiredClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::MissingRequiredClaim)
        expect(error.message).to eq("The access token is missing a required exp claim.")
      end
    end
  end

  context "with a missing_nbf_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :missing_nbf_claim)) }

    it { expect(response.reason).to eq(:missing_nbf_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises a MissingRequiredClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::MissingRequiredClaim)
        expect(error.message).to eq("The access token is missing a required nbf claim.")
      end
    end
  end

  context "with a missing_iss_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :missing_iss_claim)) }

    it { expect(response.reason).to eq(:missing_iss_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises a MissingRequiredClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::MissingRequiredClaim)
        expect(error.message).to eq("The access token is missing a required iss claim.")
      end
    end
  end

  context "with a missing_aud_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :missing_aud_claim)) }

    it { expect(response.reason).to eq(:missing_aud_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises a MissingRequiredClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::MissingRequiredClaim)
        expect(error.message).to eq("The access token is missing a required aud claim.")
      end
    end
  end

  context "with a missing_jti_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :missing_jti_claim)) }

    it { expect(response.reason).to eq(:missing_jti_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises a MissingRequiredClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::MissingRequiredClaim)
        expect(error.message).to eq("The access token is missing a required jti claim.")
      end
    end
  end

  context "with a missing_iat_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :missing_iat_claim)) }

    it { expect(response.reason).to eq(:missing_iat_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises a MissingRequiredClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::MissingRequiredClaim)
        expect(error.message).to eq("The access token is missing a required iat claim.")
      end
    end
  end

  context "with a missing_sub_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :missing_sub_claim)) }

    it { expect(response.reason).to eq(:missing_sub_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises a MissingRequiredClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::MissingRequiredClaim)
        expect(error.message).to eq("The access token is missing a required sub claim.")
      end
    end
  end

  context "with an invalid_exp_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :invalid_exp_claim)) }

    it { expect(response.reason).to eq(:invalid_exp_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises an InvalidExpClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::InvalidExpClaim)
        expect(error.message).to eq("The access token has expired.")
      end
    end
  end

  context "with an invalid_nbf_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :invalid_nbf_claim)) }

    it { expect(response.reason).to eq(:invalid_nbf_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises an InvalidNbfClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::InvalidNbfClaim)
        expect(error.message).to eq("The access token is not yet valid.")
      end
    end
  end

  context "with an invalid_iss_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :invalid_iss_claim)) }

    it { expect(response.reason).to eq(:invalid_iss_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises an InvalidIssClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::InvalidIssClaim)
        expect(error.message).to eq("The access token is from an unknown issuer.")
      end
    end
  end

  context "with an invalid_jti_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :invalid_jti_claim)) }

    it { expect(response.reason).to eq(:invalid_jti_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises an InvalidJtiClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::InvalidJtiClaim)
        expect(error.message).to eq("The access token was revoked.")
      end
    end
  end

  context "with an invalid_sub_claim invalid token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, invalid_token_reason: :invalid_sub_claim)) }

    it { expect(response.reason).to eq(:invalid_sub_claim) }
    it { expect(response.status).to eq(:unauthorized) }

    it "raises an InvalidSubClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::InvalidSubClaim)
        expect(error.message).to eq("The access token is for a different subject.")
      end
    end
  end
end

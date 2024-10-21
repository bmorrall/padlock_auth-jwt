require "rails_helper"

RSpec.describe PadlockAuth::Jwt::Http::ForbiddenTokenResponse do
  context "with an invalid_aud_claim forbidden token reason" do
    subject(:response) { described_class.from_access_token(instance_double(PadlockAuth::Jwt::AccessToken, forbidden_token_reason: :invalid_aud_claim), ["public"]) }

    it { expect(response.reason).to eq(:invalid_aud_claim) }
    it { expect(response.status).to eq(:forbidden) }

    it "raises an InvalidAudClaim error" do
      expect { response.raise_exception! }.to raise_error do |error|
        expect(error).to be_a(PadlockAuth::Jwt::Errors::InvalidAudClaim)
        expect(error.message).to eq('Access to this resource requires audience "public".')
      end
    end
  end
end

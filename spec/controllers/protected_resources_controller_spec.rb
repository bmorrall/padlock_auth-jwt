require "rails_helper"

require "jwt"

RSpec.describe "ProtectedResourcesController", type: :controller do
  controller do
    before_action -> { padlock_authorize! "example" }

    def index
      render plain: "index"
    end
  end

  let(:bearer_token) { SecureRandom.hex(16) }
  let(:access_token) { instance_double(PadlockAuth::Jwt::AccessToken, acceptable?: true) }

  before do
    allow(PadlockAuth::Jwt::AccessToken).to receive(:new).and_return(access_token)
  end

  context "when secured by a jwt strategy", :aggregate_failures do
    before do
      PadlockAuth.configure do
        secure_with(:jwt) do
          secret_key "my$ecretK3y"
          algorithm "HS256"
        end
      end
    end

    it "accepts requests with an Authorization header" do
      expect(PadlockAuth::Jwt::AccessToken).to receive(:new)
        .with(bearer_token, an_instance_of(PadlockAuth::Jwt::Strategy))
        .and_return(access_token)

      request.headers["Authorization"] = "Bearer #{bearer_token}"

      get :index

      expect(response).to have_http_status(:ok)
    end

    it "accepts requests with an access_token param" do
      expect(PadlockAuth::Jwt::AccessToken).to receive(:new)
        .with(bearer_token, an_instance_of(PadlockAuth::Jwt::Strategy))
        .and_return(access_token)

      expect(access_token).to receive(:acceptable?).and_return(true)

      get :index, params: {access_token: bearer_token}

      expect(response).to have_http_status(:ok)
    end

    it "accepts requests with a bearer token param" do
      expect(PadlockAuth::Jwt::AccessToken).to receive(:new)
        .with(bearer_token, an_instance_of(PadlockAuth::Jwt::Strategy))
        .and_return(access_token)

      expect(access_token).to receive(:acceptable?).and_return(true)

      get :index, params: {bearer_token: bearer_token}

      expect(response).to have_http_status(:ok)
    end

    it "rejects requests without an access token" do
      get :index

      expect(response).to have_http_status(:unauthorized)
    end

    it "checks if the access token is acceptable" do
      expect(access_token).to receive(:acceptable?).with(["example"]).and_return(true)

      request.headers["Authorization"] = "Bearer #{bearer_token}"

      get :index
    end

    it "rejects requests with an invalid access token" do
      allow(access_token).to receive(:acceptable?).and_return(false)
      allow(access_token).to receive(:accessible?).and_return(false)
      allow(access_token).to receive(:invalid_token_reason).and_return(:invalid_signature)

      request.headers["Authorization"] = "Bearer #{bearer_token}"

      get :index

      expect(response).to have_http_status(:unauthorized)
    end

    it "forbids requests with a forbidden access token" do
      allow(access_token).to receive(:acceptable?).and_return(false)
      allow(access_token).to receive(:accessible?).and_return(true)
      allow(access_token).to receive(:includes_scope?).and_return(false)
      allow(access_token).to receive(:forbidden_token_reason).and_return(:invalid_aud_claim)

      request.headers["Authorization"] = "Bearer #{bearer_token}"

      get :index

      expect(response).to have_http_status(:forbidden)
    end
  end

  context "when secured by a jwt strategy with raise on errors", :aggregate_failures do
    before do
      PadlockAuth.configure do
        secure_with(:jwt) do
          secret_key "my$ecretK3y"
          algorithm "HS256"
        end

        raise_on_errors!
      end
    end

    it "raises an exception when no access token is provided" do
      expect do
        get :index
      end.to raise_error(PadlockAuth::Errors::TokenUnknown, "The access token is invalid.")
    end

    it "raises an exception with an invalid access token" do
      allow(access_token).to receive(:acceptable?).and_return(false)
      allow(access_token).to receive(:accessible?).and_return(false)
      allow(access_token).to receive(:invalid_token_reason).and_return(:invalid_signature)

      request.headers["Authorization"] = "Bearer #{bearer_token}"

      expect do
        get :index
      end.to raise_error(PadlockAuth::Errors::InvalidToken, "The access token has an invalid signature.")
    end

    it "raises an exception with a forbidden access token" do
      allow(access_token).to receive(:acceptable?).and_return(false)
      allow(access_token).to receive(:accessible?).and_return(true)
      allow(access_token).to receive(:includes_scope?).and_return(false)
      allow(access_token).to receive(:forbidden_token_reason).and_return(:invalid_aud_claim)

      request.headers["Authorization"] = "Bearer #{bearer_token}"

      expect do
        get :index
      end.to raise_error(PadlockAuth::Errors::TokenForbidden, 'Access to this resource requires audience "example".')
    end
  end
end

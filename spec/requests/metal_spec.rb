RSpec.describe "Metal" do
  def secure_with_jwt!
    PadlockAuth.configure do
      secure_with(:jwt) do
        secret_key "my$ecretK3y"
        algorithm "HS256"
      end
    end
  end

  describe "GET /metal", :aggregate_failures do
    it "accepts requests with a valid token" do
      secure_with_jwt!
      token = build_jwt_token

      get "/metal.json?access_token=#{token}"

      expect(response).to have_http_status(:ok)
      expect(response.body).to eq({ok: true}.to_json)
    end

    it "rejects requests with an invalid secret_key" do
      secure_with_jwt!
      token = build_jwt_token("invalid")

      get "/metal.json?access_token=#{token}"

      expect(response).to have_http_status(:unauthorized)
      expect(response.body).to be_blank
      expect(headers["Cache-Control"]).to eq "no-store"
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token has an invalid signature."'
    end

    it "rejects requests without a token" do
      secure_with_jwt!

      get "/metal.json"

      expect(response).to have_http_status(:unauthorized)
      expect(response.body).to be_blank
      expect(headers["Cache-Control"]).to eq "no-store"
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token is invalid."'
    end
  end
end

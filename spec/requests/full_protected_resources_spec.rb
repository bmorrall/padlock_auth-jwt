require "rails_helper"

RSpec.describe "FullProtectedResources", type: :request do
  def secure_with_jwt!(**options, &)
    PadlockAuth.configure do
      secure_with(:jwt) do
        secret_key(options.delete(:secret_key) || "my$ecretK3y")
        algorithm(options.delete(:algorithm) || "HS256")

        options.each do |key, value|
          send(key, value)
        end
      end
    end
  end

  describe "GET /full_protected_resources", :aggregate_failures do
    # FullProtectedResources#index is protected by padlock_authorize! without any scopes

    it "accepts request with valid token" do
      secure_with_jwt!
      token = build_jwt_token

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:ok)
      expect(headers["WWW-Authenticate"]).to be_nil
      expect(response.body).to eq("index")
    end

    it "rejects requests with a non-JWT token" do
      secure_with_jwt!
      token = "not a jwt token"

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to match(
        "error" => "invalid_grant",
        "error_description" => "The access token is not a valid JWT."
      )
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token is not a valid JWT."'
    end

    it "rejects request with invalid secret_key" do
      secure_with_jwt!
      token = build_jwt_token("invalid")

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to match(
        "error" => "invalid_grant",
        "error_description" => "The access token has an invalid signature."
      )
      expect(headers["Cache-Control"]).to eq "no-store"
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token has an invalid signature."'
    end

    it "rejects request with invalid algorithm" do
      secure_with_jwt!
      token = build_jwt_token("my$ecretK3y", "HS512")

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to match(
        "error" => "invalid_grant",
        "error_description" => "The access token has an invalid signature."
      )
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token has an invalid signature."'
    end

    it "rejects tokens that do not match a required issuer" do
      secure_with_jwt!(issuers: ["valid"])
      token = build_jwt_token(iss: "invalid")

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to match(
        "error" => "invalid_grant",
        "error_description" => "The access token is from an unknown issuer."
      )
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token is from an unknown issuer."'
    end

    it "rejects tokens that do not match a required subject" do
      secure_with_jwt!(subject: "valid")
      token = build_jwt_token(sub: "invalid")

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to match(
        "error" => "invalid_grant",
        "error_description" => "The access token is for a different subject."
      )
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token is for a different subject."'
    end

    it "rejects expired token" do
      secure_with_jwt!
      token = build_jwt_token(exp: 1.minute.ago.to_i)

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to match(
        "error" => "invalid_grant",
        "error_description" => "The access token has expired."
      )
      expect(headers["Cache-Control"]).to eq "no-store"
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token has expired."'
    end

    it "rejects tokens which are before the not before claim" do
      secure_with_jwt!
      token = build_jwt_token(nbf: 1.minute.from_now.to_i)

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to match(
        "error" => "invalid_grant",
        "error_description" => "The access token is not yet valid."
      )
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token is not yet valid."'
    end

    it "forbids tokens with invalid audience" do
      PadlockAuth.configure do
        secure_with(:jwt) do
          secret_key "my$ecretK3y"
          algorithm "HS256"
        end

        default_scopes :valid
      end
      token = build_jwt_token(aud: "invalid")

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body).to match(
        "error" => "invalid_scope",
        "error_description" => 'Access to this resource requires audience "valid".'
      )
      expect(headers["Cache-Control"]).to eq "no-store"
      expect(headers["WWW-Authenticate"]).to be_nil
    end

    it "rejects tokens with reused jti claim" do
      secure_with_jwt! verify_jti: ->(jti) { jti != "unused" }
      token = build_jwt_token(jti: "unused")

      get "/full_protected_resources", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body).to match(
        "error" => "invalid_grant",
        "error_description" => "The access token was revoked."
      )
      expect(headers["WWW-Authenticate"]).to eq 'Bearer realm="PadlockAuth", error="invalid_grant", error_description="The access token was revoked."'
    end
  end

  describe "GET /full_protected_resources/1.json", :aggregate_failures do
    # FullProtectedResources#show is protected by padlock_authorize! with :admin and :write scopes

    it "allows tokens with one of the allowed scopes" do
      secure_with_jwt!
      token = build_jwt_token(aud: "admin")

      get "/full_protected_resources/1.json", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:ok)
      expect(headers["WWW-Authenticate"]).to be_nil
      expect(response.body).to eq("show")
    end

    it "allows tokens with another of the allowed scopes" do
      secure_with_jwt!
      token = build_jwt_token(aud: "write")

      get "/full_protected_resources/1.json", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:ok)
      expect(headers["WWW-Authenticate"]).to be_nil
      expect(response.body).to eq("show")
    end

    it "allows tokens with both allowed scopes" do
      secure_with_jwt!
      token = build_jwt_token(aud: ["write", "admin"])

      get "/full_protected_resources/1.json", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:ok)
      expect(headers["WWW-Authenticate"]).to be_nil
      expect(response.body).to eq("show")
    end

    it "allows tokens with one of the allowed scopes and additional scopes" do
      secure_with_jwt!
      token = build_jwt_token(aud: ["write", "extra"])

      get "/full_protected_resources/1.json", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:ok)
      expect(headers["WWW-Authenticate"]).to be_nil
      expect(response.body).to eq("show")
    end

    it "forbids tokens with no audience" do
      secure_with_jwt!
      token = build_jwt_token(aud: nil)

      get "/full_protected_resources/1.json", headers: {"Authorization" => "Bearer #{token}"}

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body).to match(
        "error" => "invalid_scope",
        "error_description" => 'Access to this resource requires audience "write admin".'
      )
      expect(headers["Cache-Control"]).to eq "no-store"
      expect(headers["WWW-Authenticate"]).to be_nil
    end
  end
end

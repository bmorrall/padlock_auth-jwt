module PadlockAuth
  module Jwt
    module Http
      # Adds JWT specific errors to the InvalidTokenResponse
      class InvalidTokenResponse < PadlockAuth::Http::InvalidTokenResponse
        protected

        def exception_class
          jwt_errors_mapping.fetch(reason) { super }
        end

        private

        def jwt_errors_mapping
          {
            invalid_signature: PadlockAuth::Jwt::Errors::InvalidSignature,
            missing_exp_claim: PadlockAuth::Jwt::Errors::MissingRequiredClaim,
            missing_nbf_claim: PadlockAuth::Jwt::Errors::MissingRequiredClaim,
            missing_iss_claim: PadlockAuth::Jwt::Errors::MissingRequiredClaim,
            missing_aud_claim: PadlockAuth::Jwt::Errors::MissingRequiredClaim,
            missing_jti_claim: PadlockAuth::Jwt::Errors::MissingRequiredClaim,
            missing_iat_claim: PadlockAuth::Jwt::Errors::MissingRequiredClaim,
            missing_sub_claim: PadlockAuth::Jwt::Errors::MissingRequiredClaim,
            invalid_exp_claim: PadlockAuth::Jwt::Errors::InvalidExpClaim,
            invalid_nbf_claim: PadlockAuth::Jwt::Errors::InvalidNbfClaim,
            invalid_iss_claim: PadlockAuth::Jwt::Errors::InvalidIssClaim,
            invalid_jti_claim: PadlockAuth::Jwt::Errors::InvalidJtiClaim,
            invalid_sub_claim: PadlockAuth::Jwt::Errors::InvalidSubClaim

          }
        end
      end
    end
  end
end

module PadlockAuth
  module Jwt
    module Errors
      # Invalid Token errors

      class InvalidSignature < PadlockAuth::Errors::InvalidToken; end

      class MissingRequiredClaim < PadlockAuth::Errors::InvalidToken; end

      class InvalidExpClaim < PadlockAuth::Errors::TokenExpired; end

      class InvalidNbfClaim < PadlockAuth::Errors::InvalidToken; end

      class InvalidIssClaim < PadlockAuth::Errors::InvalidToken; end

      class InvalidJtiClaim < PadlockAuth::Errors::TokenRevoked; end

      class InvalidSubClaim < PadlockAuth::Errors::InvalidToken; end

      # Forbidden Token errors

      class InvalidAudClaim < PadlockAuth::Errors::TokenForbidden; end
    end
  end
end

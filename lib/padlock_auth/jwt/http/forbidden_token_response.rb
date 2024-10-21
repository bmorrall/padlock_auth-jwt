module PadlockAuth
  module Jwt
    module Http
      # Adds JWT specific errors to the ForbiddenTokenResponse
      class ForbiddenTokenResponse < PadlockAuth::Http::ForbiddenTokenResponse
        protected

        def exception_class
          PadlockAuth::Jwt::Errors::InvalidAudClaim
        end
      end
    end
  end
end

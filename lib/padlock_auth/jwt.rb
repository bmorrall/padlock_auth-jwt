require "padlock_auth"

require "padlock_auth/jwt/version"
require "padlock_auth/jwt/errors"

module PadlockAuth
  module Jwt
    autoload :AccessToken, "padlock_auth/jwt/access_token"
    autoload :Strategy, "padlock_auth/jwt/strategy"

    module Http
      autoload :InvalidTokenResponse, "padlock_auth/jwt/http/invalid_token_response"
      autoload :ForbiddenTokenResponse, "padlock_auth/jwt/http/forbidden_token_response"
    end
  end
end

require "padlock_auth/jwt/railtie"

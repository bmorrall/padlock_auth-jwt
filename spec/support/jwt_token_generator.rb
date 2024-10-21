module PadlockAuth
  module JwtTokenGenerator
    def build_jwt_token(secret_key = "my$ecretK3y", algorithm = "HS256", **options)
      JWT.encode(options.reverse_merge(
        exp: 1.minute.since.to_i,
        aud: "PadlockAuthTest",
        jti: SecureRandom.uuid,
        iat: Time.zone.now.to_i,
        sub: "AuthSubject#{SecureRandom.hex(4)}"
      ), secret_key, algorithm, {typ: "at+jwt"})
    end
  end
end

RSpec.configure do |config|
  config.include PadlockAuth::JwtTokenGenerator
end

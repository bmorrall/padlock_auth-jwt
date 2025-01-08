require "jwt"

module PadlockAuth
  module Jwt
    class AccessToken < PadlockAuth::AbstractAccessToken
      def initialize(jwt, strategy)
        @jwt = jwt
        @encoded_token = JWT::EncodedToken.new(jwt)
        @strategy = strategy
      end

      def accessible?
        return false unless valid_jwt_token?

        return false unless includes_required_claims?

        # "exp" (Expiration Time) Claim
        return false unless valid_exp_claim?

        # "nbf" (Not Before) Claim
        return false unless valid_nbf_claim?

        # "iss" (Issuer) Claim
        return false unless valid_iss_claim?

        # "jti" (JWT ID) Claim
        return false unless valid_jti_claim?

        # "sub" (Subject) Claim
        return false unless valid_sub_claim?

        true
      end

      def invalid_token_reason
        return valid_header? ? :invalid_signature : :invalid_jwt_token unless valid_jwt_token?

        return :missing_exp_claim unless includes_required_exp_claim?
        return :invalid_exp_claim unless valid_exp_claim?

        return :missing_nbf_claim unless includes_required_nbf_claim?
        return :invalid_nbf_claim unless valid_nbf_claim?

        return :missing_iss_claim unless includes_required_iss_claim?
        return :invalid_iss_claim unless valid_iss_claim?

        return :missing_aud_claim unless includes_required_aud_claim?
        # validity checked by #includes_scope?

        return :missing_jti_claim unless includes_required_jti_claim?
        return :invalid_jti_claim unless valid_jti_claim?

        return :missing_iat_claim unless includes_required_iat_claim?

        return :missing_sub_claim unless includes_required_sub_claim?
        return :invalid_sub_claim unless valid_sub_claim?

        super # :unknown
      end

      def includes_scope?(required_scopes)
        return false unless valid_jwt_token?

        required_scopes.none? || valid_aud_claim?(required_scopes.map(&:to_s))
      end

      def forbidden_token_reason
        return :invalid_jwt_token unless valid_jwt_token?

        :invalid_aud_claim
      end

      def header
        @encoded_token.header if valid_jwt_token?
      end

      def payload
        @encoded_token.payload if valid_jwt_token?
      end

      private

      def valid_jwt_token?
        valid_signature? && valid_header?
      end

      # https://datatracker.ietf.org/doc/html/rfc9068#JWTATLValidate
      # The resource server MUST verify that the "typ" header value is "at+jwt" or "application/at+jwt" and reject tokens carrying any other value.
      def valid_header?
        return @valid_header if instance_variable_defined?(:@valid_header)
        @valid_header = @encoded_token.header.present? &&
          @strategy.header_types.include?(@encoded_token.header["typ"])
      rescue JWT::DecodeError
        @valid_header = false
      end

      def valid_signature?
        return @valid_signature if instance_variable_defined?(:@valid_signature)
        @valid_signature = @encoded_token.valid_signature?(algorithm: @strategy.algorithm, key: @strategy.secret_key)
      rescue JWT::DecodeError
        @valid_signature = false
      end

      def includes_required_claims?
        includes_required_exp_claim? &&
          includes_required_nbf_claim? &&
          includes_required_iss_claim? &&
          includes_required_aud_claim? &&
          includes_required_jti_claim? &&
          includes_required_iat_claim? &&
          includes_required_sub_claim?
      end

      def includes_required_exp_claim?
        !@strategy.exp_required? || @encoded_token.valid_claims?(required: ["exp"])
      end

      def includes_required_nbf_claim?
        !@strategy.nbf_required? || @encoded_token.valid_claims?(required: ["nbf"])
      end

      def includes_required_iss_claim?
        !@strategy.iss_required? || @encoded_token.valid_claims?(required: ["iss"])
      end

      def includes_required_aud_claim?
        !@strategy.aud_required? || @encoded_token.valid_claims?(required: ["aud"])
      end

      def includes_required_jti_claim?
        !@strategy.jti_required? || @encoded_token.valid_claims?(required: ["jti"])
      end

      def includes_required_iat_claim?
        !@strategy.iat_required? || @encoded_token.valid_claims?(required: ["iat"])
      end

      def includes_required_sub_claim?
        !@strategy.sub_required? || @encoded_token.valid_claims?(required: ["sub"])
      end

      def valid_exp_claim?
        return @valid_exp_claim if instance_variable_defined?(:@valid_exp_claim)
        @valid_exp_claim = @encoded_token.valid_claims?(exp: {leeway: @strategy.expiry_leeway})
      end

      def valid_nbf_claim?
        return @valid_nbf_claim if instance_variable_defined?(:@valid_nbf_claim)
        @valid_nbf_claim = @encoded_token.valid_claims?(nbf: {leeway: @strategy.not_before_leeway})
      end

      def valid_iss_claim?
        return @valid_iss_claim if instance_variable_defined?(:@valid_iss_claim)
        @valid_iss_claim = @strategy.issuers.none? || @encoded_token.valid_claims?(iss: @strategy.issuers)
      end

      def valid_aud_claim?(required_scopes)
        @encoded_token.valid_claims?(aud: required_scopes.map(&:to_s))
      end

      def valid_jti_claim?
        return @valid_jti_claim if instance_variable_defined?(:@valid_jti_claim)
        @valid_jti_claim = @encoded_token.valid_claims?(jti: @strategy.verify_jti)
      end

      def valid_sub_claim?
        return true if @strategy.subject.blank?

        return @valid_sub_claim if instance_variable_defined?(:@valid_sub_claim)
        @valid_sub_claim = @encoded_token.valid_claims?(sub: @strategy.subject)
      end
    end
  end
end

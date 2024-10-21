module PadlockAuth
  module Jwt
    class Strategy < PadlockAuth::AbstractStrategy
      include PadlockAuth::Mixins::BuildWith

      class Builder < PadlockAuth::Utils::AbstractBuilder
        def nbf_leeway(nbf_leeway)
          not_before_leeway(nbf_leeway)
        end
      end

      build_with Builder

      extend PadlockAuth::Config::Option

      # Token Factory

      def build_access_token(raw_token)
        Jwt::AccessToken.new(raw_token, self)
      end

      # HTTP Responses

      def build_invalid_token_response(access_token)
        Jwt::Http::InvalidTokenResponse.from_access_token(access_token)
      end

      def build_forbidden_token_response(access_token, scopes)
        Jwt::Http::ForbiddenTokenResponse.from_access_token(access_token, scopes)
      end

      # Signature

      option :secret_key

      # https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
      option :algorithm, default: "RS256"

      # "typ" (Type) Header Parameter
      #
      # RFC9068 registers the "application/at+jwt" media type, which can be used to
      # indicate that the content is a JWT access token. JWT access tokens MUST include this media
      # type in the "typ" header parameter to explicitly declare that the JWT represents an access
      # token complying with this profile.

      # https://datatracker.ietf.org/doc/html/rfc9068#JWTATLValidate
      REQUIRED_HEADER_TYPES = ["at+jwt", "application/at+jwt"]

      option :header_types, default: REQUIRED_HEADER_TYPES

      def header_types
        Array.wrap(@header_types || REQUIRED_HEADER_TYPES)
      end

      # "exp" (Expiration Time) Claim
      #
      #  The "exp" (expiration time) claim identifies the expiration time on
      #  or after which the JWT MUST NOT be accepted for processing.  The
      #  processing of the "exp" claim requires that the current date/time
      #  MUST be before the expiration date/time listed in the "exp" claim.
      #
      #  Implementers MAY provide for some small leeway, usually no more than
      #  a few minutes, to account for clock skew.  Its value MUST be a number
      #  containing a NumericDate value.  Use of this claim is OPTIONAL.

      # @!attribute require_exp [r] Boolean
      option :require_exp, default: true

      def exp_required?
        !!require_exp
      end

      option :expiry_leeway, default: 0

      # "nbf" (Not Before) Claim
      #
      # The "nbf" (not before) claim identifies the time before which the JWT
      # MUST NOT be accepted for processing.  The processing of the "nbf"
      # claim requires that the current date/time MUST be after or equal to
      # the not-before date/time listed in the "nbf" claim.  Implementers MAY
      # provide for some small leeway, usually no more than a few minutes, to
      # account for clock skew.  Its value MUST be a number containing a
      # NumericDate value.  Use of this claim is OPTIONAL.

      option :require_nbf, default: false

      def nbf_required?
        !!require_nbf
      end

      option :not_before_leeway, default: 0

      # "iss" (Issuer) Claim
      #
      # The "iss" (issuer) claim identifies the principal that issued the
      # JWT.  The processing of this claim is generally application specific.
      # The "iss" value is a case-sensitive string containing a StringOrURI
      # value.  Use of this claim is OPTIONAL.

      # @!attribute require_iss [r] Boolean
      option :require_iss, default: false

      def iss_required?
        !!require_iss
      end

      option :issuers, default: nil

      def issuers
        Array.wrap(@issuers)
      end

      # "aud" (Audience) Claim
      #
      # The "aud" (audience) claim identifies the recipients that the JWT is
      # intended for.  Each principal intended to process the JWT MUST
      # identify itself with a value in the audience claim.  If the principal
      # processing the claim does not identify itself with a value in the
      # "aud" claim when this claim is present, then the JWT MUST be
      # rejected.  In the general case, the "aud" value is an array of case-
      # sensitive strings, each containing a StringOrURI value.  In the
      # special case when the JWT has one audience, the "aud" value MAY be a
      # single case-sensitive string containing a StringOrURI value.  The
      # interpretation of audience values is generally application specific.
      # Use of this claim is OPTIONAL.

      option :require_aud, default: true

      def aud_required?
        !!require_aud
      end

      # "jti" (JWT ID) Claim
      #
      # The "jti" (JWT ID) claim provides a unique identifier for the JWT.
      # The identifier value MUST be assigned in a manner that ensures that
      # there is a negligible probability that the same value will be
      # accidentally assigned to a different data object; if the application
      # uses multiple issuers, collisions MUST be prevented among values
      # produced by different issuers as well.  The "jti" claim can be used
      # to prevent the JWT from being replayed.  The "jti" value is a case-
      # sensitive string.  Use of this claim is OPTIONAL.

      option :require_jti, default: true

      def jti_required?
        !!require_jti
      end

      option :verify_jti, default: proc { true }

      # "iat" (Issued At) Claim
      #
      # The "iat" (issued at) claim identifies the time at which the JWT was
      # issued.  This claim can be used to determine the age of the JWT.  Its
      # value MUST be a number containing a NumericDate value.  Use of this
      # claim is OPTIONAL.

      option :require_iat, default: true

      def iat_required?
        !!require_iat
      end

      # "sub" (Subject) Claim
      #
      # The "sub" (subject) claim identifies the principal that is the
      # subject of the JWT.  The claims in a JWT are normally statements
      # about the subject.  The subject value MUST either be scoped to be
      # locally unique in the context of the issuer or be globally unique.
      # The processing of this claim is generally application specific.  The
      # "sub" value is a case-sensitive string containing a StringOrURI
      # value.  Use of this claim is OPTIONAL.

      option :require_sub, default: true

      def sub_required?
        !!require_sub
      end

      option :subject, default: nil

      def subject
        Array.wrap(@subject)
      end

      # Builder Validation

      def validate!
        raise ArgumentError, "secret_key is required" unless secret_key.present?

        raise ArgumentError, "algorithm is required" unless algorithm.present?

        raise ArgumentError, "header_types cannot be empty" unless header_types.present?

        if subject.present? && !sub_required?
          raise ArgumentError, "subject is not required"
        end

        if iss_required? && issuers.blank?
          raise ArgumentError, "issuers are required when require_iss is true"
        end

        true
      end
    end
  end
end

require_relative "lib/padlock_auth/jwt/version"

Gem::Specification.new do |spec|
  spec.name = "padlock_auth-jwt"
  spec.version = PadlockAuth::Jwt::VERSION
  spec.authors = ["Ben Morrall"]
  spec.email = ["bemo56@hotmail.com"]
  spec.homepage = "https://github.com/bmorrall/padlock_auth-jwt"
  spec.summary = "Adds JWT Support to PadlockAuth."
  spec.description = "Allows API endpoints to be secured by a JWT Access Token."
  spec.license = "MIT"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/main/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]
  end

  spec.add_dependency "rails", ">= 7.2.1.1"
  spec.add_dependency "jwt", ">= 2.9.3"

  spec.add_development_dependency "rspec-rails"
  spec.add_development_dependency "standard", ">= 1.41.1"
  spec.add_development_dependency "simplecov"
end

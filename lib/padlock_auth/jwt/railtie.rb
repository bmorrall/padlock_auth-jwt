module PadlockAuthJwt
  class Railtie < ::Rails::Railtie
    initializer "padlock_auth-jwt.i18n" do
      Dir.glob(File.join(File.dirname(__FILE__), "..", "..", "..", "config", "locales", "*.yml")).each do |file|
        I18n.load_path << File.expand_path(file)
      end
    end
  end
end

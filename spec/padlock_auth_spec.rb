require "rails_helper"

RSpec.describe "PadlockAuth" do
  before { PadlockAuth.remove_instance_variable(:@config) if PadlockAuth.instance_variable_defined?(:@config) }

  describe ".configure", "#secure_with" do
    it "can be configured with a jwt strategy" do
      PadlockAuth.configure do |config|
        secure_with :jwt do
          secret_key "my$ecretK3y"
          algorithm "HS256"
        end
      end

      expect(PadlockAuth.config.strategy).to be_instance_of(PadlockAuth::Jwt::Strategy)
      expect(PadlockAuth.config.strategy.secret_key).to eq("my$ecretK3y")
      expect(PadlockAuth.config.strategy.algorithm).to eq("HS256")
    end
  end
end

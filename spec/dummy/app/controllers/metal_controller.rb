# frozen_string_literal: true

class MetalController < ActionController::Metal
  include AbstractController::Callbacks
  include ActionController::Head
  include PadlockAuth::Rails::Helpers

  before_action :padlock_authorize!

  def index
    self.response_body = {ok: true}.to_json
  end
end

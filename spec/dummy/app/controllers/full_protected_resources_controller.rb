# frozen_string_literal: true

class FullProtectedResourcesController < ApplicationController
  before_action -> { padlock_authorize! :write, :admin }, only: :show
  before_action :padlock_authorize!, only: :index

  def index
    render plain: "index"
  end

  def show
    render plain: "show"
  end
end

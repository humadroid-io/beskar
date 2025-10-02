class WelcomeController < ApplicationController
  before_action :authenticate_devise_user!, only: %i[restricted]

  def index
  end

  def restricted
  end
end

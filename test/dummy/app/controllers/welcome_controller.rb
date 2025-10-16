class WelcomeController < ApplicationController
  include Authentication
  
  before_action :authenticate_devise_user!, only: %i[devise_restricted]
  before_action :resume_session, only: %i[user_restricted]
  skip_before_action :require_authentication, only: %i[index devise_restricted]

  def index
  end

  def devise_restricted
    # Only accessible to Devise users
  end
  
  def user_restricted
    # Only accessible to Rails 8 auth users (requires authentication via Authentication concern)
    # The Authentication concern's resume_session will redirect if not authenticated
  end
end

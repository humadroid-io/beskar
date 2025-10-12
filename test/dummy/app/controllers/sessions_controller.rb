class SessionsController < ApplicationController
  include Authentication
  include Beskar::Controllers::SecurityTracking
  
  allow_unauthenticated_access only: %i[ new create ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { 
    # Track rate limit hit as a security event
    track_authentication_failure(User, :user) rescue nil
    redirect_to new_session_url, alert: "Try again later." 
  }

  def new
  end

  def create
    if user = User.authenticate_by(params.permit(:email_address, :password))
      # Track successful authentication before creating session
      track_authentication_success(user)
      
      start_new_session_for user
      redirect_to after_authentication_url
    else
      # Track failed authentication attempt
      track_authentication_failure(User, :user)
      
      redirect_to new_session_path, alert: "Try another email address or password."
    end
  end

  def destroy
    # Track logout before terminating session
    track_logout(Current.session&.user) if Current.session
    
    terminate_session
    redirect_to new_session_path
  end
end

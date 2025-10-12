module Beskar
  module Controllers
    # Controller concern for tracking Rails 8 authentication events
    # 
    # Usage in SessionsController:
    #   class SessionsController < ApplicationController
    #     include Beskar::Controllers::SecurityTracking
    #     
    #     def create
    #       if user = User.authenticate_by(params.permit(:email_address, :password))
    #         track_authentication_success(user)
    #         start_new_session_for user
    #         redirect_to after_authentication_url
    #       else
    #         track_authentication_failure(User, :user)
    #         redirect_to new_session_path, alert: "Try another email address or password."
    #       end
    #     end
    #   end
    module SecurityTracking
      extend ActiveSupport::Concern

      private

      # Track successful authentication for a user
      # This should be called after verifying credentials but before creating session
      def track_authentication_success(user)
        return unless user
        return unless Beskar.configuration.track_successful_logins?

        user.track_authentication_event(request, :success)
        Rails.logger.info "[Beskar] Tracked successful authentication for user #{user.id}"
      rescue => e
        Rails.logger.error "[Beskar] Failed to track authentication success: #{e.message}"
      end

      # Track failed authentication attempt
      # This should be called when authentication fails
      def track_authentication_failure(model_class, scope = :user)
        return unless Beskar.configuration.track_failed_logins?

        model_class.track_failed_authentication(request, scope)
        Rails.logger.info "[Beskar] Tracked failed authentication for scope #{scope}"
      rescue => e
        Rails.logger.error "[Beskar] Failed to track authentication failure: #{e.message}"
      end

      # Track logout event
      def track_logout(user)
        return unless user
        return unless Beskar.configuration.security_tracking_enabled?

        user.security_events.create!(
          event_type: "logout",
          ip_address: request.ip,
          user_agent: request.user_agent,
          metadata: {
            timestamp: Time.current.iso8601,
            session_id: request.session.id,
            request_path: request.path
          },
          risk_score: 0
        )
        Rails.logger.info "[Beskar] Tracked logout for user #{user.id}"
      rescue => e
        Rails.logger.error "[Beskar] Failed to track logout: #{e.message}"
      end
    end
  end
end

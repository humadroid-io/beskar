module Beskar
  module Models
    # Rails 8 authentication-specific security tracking functionality
    # This module provides security tracking for models using has_secure_password
    # and session-based authentication (Rails 8 built-in authentication)
    module SecurityTrackableAuthenticable
      extend ActiveSupport::Concern

      included do
        # Include the generic functionality first
        include Beskar::Models::SecurityTrackableGeneric

        # No automatic callbacks like Devise - tracking is done explicitly
        # in controllers via the Beskar::Controllers::SecurityTracking concern
      end

      # Make handle_high_risk_lock public (it's private in Generic)
      public
      
      # Rails 8 auth-specific: Handle high risk lock by destroying sessions
      # Public method called when high-risk event is detected
      def handle_high_risk_lock(security_event, request)
        reason = determine_lock_reason(security_event)
        
        Beskar::Logger.warn("Rails auth high-risk lock detected: #{reason}")
        
        # Destroy all sessions to immediately lock out attacker
        destroy_all_sessions(except: request.session.id)
        
        # Check if this warrants emergency password reset
        if should_reset_password?(security_event, reason)
          perform_emergency_password_reset(security_event, reason)
        end
      end

      # Destroy all user sessions (for impossible travel / high-risk scenarios)
      def destroy_all_sessions(except: nil)
        if respond_to?(:sessions) && sessions.respond_to?(:destroy_all)
          if except
            # Keep current session but destroy all others
            sessions.where.not(id: except).destroy_all
            Beskar::Logger.info("Destroyed #{sessions.count} sessions except current")
          else
            # Destroy ALL sessions including current
            count = sessions.count
            sessions.destroy_all
            Beskar::Logger.info("Destroyed all #{count} sessions")
          end
        else
          Beskar::Logger.warn("Model does not have sessions association, cannot destroy sessions")
        end
      rescue => e
        Beskar::Logger.error("Failed to destroy sessions: #{e.message}")
      end

      # Determine if emergency password reset is warranted
      def should_reset_password?(security_event, reason)
        config = Beskar.configuration.emergency_password_reset
        return false unless config[:enabled]

        case reason
        when :impossible_travel
          # Count impossible travel events in recent history
          recent_impossible_travel = security_events
            .where(event_type: ["account_locked", "login_success"])
            .where("created_at >= ?", 24.hours.ago)
            .where("metadata->>'geolocation' LIKE ?", '%impossible_travel%')
            .count
          
          recent_impossible_travel >= (config[:impossible_travel_threshold] || 3)
          
        when :suspicious_device
          # Multiple suspicious device logins
          recent_suspicious = security_events
            .where(event_type: "account_locked")
            .where("created_at >= ?", 24.hours.ago)
            .where("metadata->>'device_info' LIKE ?", '%suspicious%')
            .count
          
          recent_suspicious >= (config[:suspicious_device_threshold] || 5)
          
        else
          # For other reasons, check total lock count
          recent_locks = security_events
            .where(event_type: "account_locked")
            .where("created_at >= ?", 24.hours.ago)
            .count
          
          recent_locks >= (config[:total_locks_threshold] || 5)
        end
      end

      # Perform emergency password reset
      def perform_emergency_password_reset(security_event, reason)
        config = Beskar.configuration.emergency_password_reset
        
        # Generate a cryptographically secure random password
        new_password = SecureRandom.base58(32)
        
        begin
          # Update password
          update!(password: new_password, password_confirmation: new_password)
          
          # Log the reset event
          security_events.create!(
            event_type: "emergency_password_reset",
            ip_address: security_event.ip_address,
            user_agent: security_event.user_agent,
            metadata: {
              reason: reason.to_s,
              triggering_event_id: security_event.id,
              timestamp: Time.current.iso8601,
              reset_method: "automatic"
            },
            risk_score: 100
          )
          
          # Send notification to user
          if config[:send_notification]
            send_emergency_reset_notification(reason)
          end
          
          # Notify security team
          if config[:notify_security_team]
            notify_security_team_of_reset(reason, security_event)
          end
          
          Beskar::Logger.warn("Emergency password reset performed for user #{id}, reason: #{reason}")
          
        rescue => e
          Beskar::Logger.error("Failed to perform emergency password reset: #{e.message}")
          
          # Create failed reset event
          security_events.create!(
            event_type: "emergency_password_reset_failed",
            ip_address: security_event.ip_address,
            user_agent: security_event.user_agent,
            metadata: {
              reason: reason.to_s,
              error: e.message,
              timestamp: Time.current.iso8601
            },
            risk_score: 100
          )
        end
      end

      # Send notification to user about emergency password reset
      def send_emergency_reset_notification(reason)
        # This should be implemented by the application
        # Example: UserMailer.emergency_password_reset(self, reason).deliver_later
        Beskar::Logger.info("Would send emergency reset notification to user #{id}")
      rescue => e
        Beskar::Logger.error("Failed to send emergency reset notification: #{e.message}")
      end

      # Notify security team about emergency password reset
      def notify_security_team_of_reset(reason, security_event)
        # This should be implemented by the application
        # Example: SecurityMailer.emergency_reset_alert(self, reason, security_event).deliver_later
        Beskar::Logger.info("Would notify security team about reset for user #{id}")
      rescue => e
        Beskar::Logger.error("Failed to notify security team: #{e.message}")
      end
    end
  end
end

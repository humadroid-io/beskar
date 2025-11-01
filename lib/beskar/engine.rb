module Beskar
  class Engine < ::Rails::Engine
    isolate_namespace Beskar

    initializer "beskar.middleware" do |app|
      app.config.middleware.use ::Beskar::Middleware::RequestAnalyzer
    end

    # Preload banned IPs into cache on startup
    config.after_initialize do
      if defined?(Beskar::BannedIp)
        Rails.application.executor.wrap do
          Beskar::BannedIp.preload_cache!
          Beskar::Logger.info("Preloaded banned IPs into cache")
        rescue => e
          Beskar::Logger.warn("Failed to preload banned IPs: #{e.message}")
        end
      end
    end

    initializer "beskar.warden_callbacks", after: :load_config_initializers do |app|
      if defined?(Warden)
        # Track successful authentication and check for high-risk locks
        Warden::Manager.after_set_user except: :fetch do |user, auth, opts|
          # Only proceed if Beskar security tracking is available and enabled
          if user.respond_to?(:track_authentication_event) && auth.request
            # Track the authentication event (creates security event)
            security_event = user.track_authentication_event(auth.request, :success)

            # Check if account was locked due to high risk (only if immediate_signout is enabled)
            # This happens AFTER successful authentication but BEFORE the request completes
            # Requires :lockable module to be enabled on the user model
            if Beskar.configuration.immediate_signout? &&
               Beskar.configuration.risk_based_locking_enabled? &&
               security_event &&
               user_was_just_locked?(user, security_event) &&
               user.respond_to?(:access_locked?) && user.access_locked?
              Beskar::Logger.warn("Signing out user #{user.id} due to high-risk lock")
              auth.logout
              throw :warden, scope: opts[:scope], message: :account_locked_due_to_high_risk
            end
          end
        end

        # Alternative approach using after_authentication is available but not enabled by default
        # Uncomment this to use the alternative approach (more targeted, only on authentication)
        # Warden::Manager.after_authentication do |user, auth, opts|
        #   if user.respond_to?(:check_high_risk_lock_and_signout)
        #     user.check_high_risk_lock_and_signout(auth)
        #   end
        # end

        Warden::Manager.before_failure do |env, opts|
          if env
            request = ActionDispatch::Request.new(env)
            scope = opts[:scope]
            
            # Try to get model class from configuration
            model_class = Beskar.configuration&.model_class_for_scope(scope)
            
            if model_class && model_class.respond_to?(:track_failed_authentication)
              model_class.track_failed_authentication(request, scope)
            else
              Beskar::Logger.debug("No trackable model found for scope: #{scope}")
            end
          end
        end
      end
    end

    # Helper method to check if user was just locked
    def self.user_was_just_locked?(user, security_event)
      return false unless Beskar.configuration.risk_based_locking_enabled?
      return false unless security_event
      return false unless user&.respond_to?(:security_events)

      # Check if an account_locked or lock_attempted event was just created
      recent_lock = user.security_events
        .where(event_type: [ "account_locked", "lock_attempted" ])
        .where("created_at >= ?", 10.seconds.ago)
        .order(created_at: :desc)
        .first

      recent_lock.present?
    end

    # Add engine migrations to host app's migration paths
    initializer "beskar.append_migrations" do |app|
      # Don't add migrations if we're inside the engine itself (testing)
      if !root.to_s.include?(app.root.to_s) && !app.root.to_s.include?(root.to_s)
        engine_migrations = root.join("db", "migrate").to_s

        # Add to Rails paths
        app.config.paths["db/migrate"] << engine_migrations
      end
    end

    # Ensure ActiveRecord sees the engine migrations after initialization
    # config.after_initialize do |app|
    #   unless root.to_s.include?(app.root.to_s)
    #     engine_migrations = root.join("db", "migrate").to_s

    #     # Update ActiveRecord::Tasks paths
    #     current_paths = Array(ActiveRecord::Tasks::DatabaseTasks.migrations_paths)
    #     current_paths << engine_migrations
    #     ActiveRecord::Tasks::DatabaseTasks.migrations_paths = current_paths.uniq
    #   end
    # end
  end
end

# frozen_string_literal: true

require "rails/generators"
require "rails/generators/migration"

module Beskar
  module Generators
    class InstallGenerator < Rails::Generators::Base
      include Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      desc "Creates a Beskar initializer and runs migrations"

      def self.next_migration_number(path)
        if @prev_migration_nr
          @prev_migration_nr += 1
        else
          @prev_migration_nr = Time.now.utc.strftime("%Y%m%d%H%M%S").to_i
        end
        @prev_migration_nr.to_s
      end

      def copy_initializer
        template "initializer.rb.tt", "config/initializers/beskar.rb"
      end

      def mount_engine
        route_text = "mount Beskar::Engine => '/beskar'"

        # Check if the route already exists
        if File.read("config/routes.rb").include?(route_text)
          say "Route already mounted, skipping...", :yellow
        else
          route route_text
          say "Mounted Beskar engine at /beskar", :green
        end
      end

      def copy_migrations
        # Copy migrations from the engine to the host app
        migration_source = File.expand_path("../../../../../db/migrate", __dir__)

        if Dir.exist?(migration_source)
          Dir.glob("#{migration_source}/*.rb").each do |migration|
            migration_name = File.basename(migration).sub(/^\d+_/, "")

            # Check if migration already exists
            if migration_already_exists?(migration_name)
              say "Migration #{migration_name} already exists, skipping...", :yellow
            else
              migration_template migration, "db/migrate/#{migration_name}"
            end
          end
        end

        say "Migrations copied. Run 'rails db:migrate' to create the tables.", :green
      end

      # CSS Zero is no longer required - styles are embedded in the dashboard
      # def install_css_zero
      #   # Removed - dashboard now uses embedded styles
      # end

      def show_readme
        readme_content = <<~README

          ===============================================================================
          🛡️  Beskar Installation Complete!
          ===============================================================================

          Next steps:

          1. Run migrations to create the security tables:
             $ rails db:migrate

          2. Configure authentication for the dashboard in config/initializers/beskar.rb

             For Devise users:
             config.authenticate_admin = proc do
               authenticate_admin!
             end

             For custom authentication:
             config.authenticate_admin = proc do
               redirect_to main_app.root_path unless current_user&.admin?
             end

          3. Add Beskar concerns to your User model (or authentication model):

             class User < ApplicationRecord
               include Beskar::Models::SecurityTrackable

               # For Devise users, also add:
               include Beskar::Models::SecurityTrackableDevise
             end

          4. Access the security dashboard at:
             http://localhost:3000/beskar

          5. Optional: Configure additional settings in config/initializers/beskar.rb
             - IP whitelist
             - WAF rules
             - Rate limiting
             - Geolocation
             - Risk-based locking

          ===============================================================================
          📚 Documentation
          ===============================================================================

          Dashboard Guide: https://github.com/humadroid-io/beskar/blob/main/DASHBOARD.md
          Configuration: https://github.com/humadroid-io/beskar/blob/main/README.md

          ===============================================================================
          ⚠️  Important for Production
          ===============================================================================

          1. ALWAYS configure authentication for the dashboard
          2. Set monitor_only = false when ready to block threats
          3. Configure your IP whitelist to prevent locking yourself out
          4. Set up database indexes for large-scale deployments:

             $ rails generate beskar:indexes
             $ rails db:migrate

          ===============================================================================
          💡 Quick Tips
          ===============================================================================

          - Start with monitor_only = true to observe without blocking
          - Use the dashboard to review security events before enabling blocking
          - Configure email notifications for high-risk events
          - Export security data regularly for analysis
          - Consider implementing custom risk scoring for your use case

          ===============================================================================

        README

        say readme_content, :green
      end

      private

      def migration_already_exists?(migration_name)
        Dir.glob("db/migrate/*_#{migration_name}").any?
      end

      def migration_template(source, destination)
        migration_number = self.class.next_migration_number(nil)
        file_name = "#{migration_number}_#{destination}"

        copy_file source, file_name
      end
    end
  end
end

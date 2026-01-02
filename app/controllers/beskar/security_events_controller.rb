require "csv"

module Beskar
  class SecurityEventsController < ApplicationController
    def index
      @events = Beskar::SecurityEvent.preload(:user).order(created_at: :desc)

      # Apply filters
      apply_filters!

      # Paginate results
      @pagination = paginate(@events, per_page: params[:per_page]&.to_i || 25)
      @events = @pagination[:records]

      # Get filter options for dropdowns
      @event_types = Beskar::SecurityEvent.distinct.pluck(:event_type).sort
      @risk_levels = ["low", "medium", "high", "critical"]
    end

    def show
      @event = Beskar::SecurityEvent.find(params[:id])

      # Find related events
      @related_events = Beskar::SecurityEvent
        .where.not(id: @event.id)
        .where(ip_address: @event.ip_address)
        .order(created_at: :desc)
        .limit(10)

      # Get user's recent events if user exists
      if @event.user.present?
        @user_events = @event.user.security_events
          .where.not(id: @event.id)
          .order(created_at: :desc)
          .limit(10)
      end

      # Check if IP is banned
      @ip_ban = Beskar::BannedIp.find_by(ip_address: @event.ip_address)
    end

    def export
      @events = Beskar::SecurityEvent.preload(:user)

      # Apply same filters as index
      apply_filters!

      respond_to do |format|
        format.csv do
          send_data generate_csv(@events),
            filename: "security-events-#{Date.current}.csv",
            type: "text/csv"
        end
        format.json do
          render json: @events.as_json(
            include: {user: {only: [:id, :email]}},
            except: [:updated_at]
          )
        end
      end
    end

    private

    def apply_filters!
      # Filter by event type
      if params[:event_type].present?
        @events = @events.where(event_type: params[:event_type])
      end

      # Filter by risk level
      if params[:risk_level].present?
        @events = case params[:risk_level]
        when "low"
          @events.where("risk_score < 30")
        when "medium"
          @events.where("risk_score BETWEEN 30 AND 60")
        when "high"
          @events.where("risk_score BETWEEN 61 AND 85")
        when "critical"
          @events.where("risk_score > 85")
        else
          @events
        end
      end

      # Filter by IP address
      if params[:ip_address].present?
        @events = @events.where("ip_address LIKE ?", "%#{params[:ip_address]}%")
      end

      # Filter by user email (if attempted_email is stored)
      if params[:email].present?
        # Search in attempted_email column and metadata (avoid joining polymorphic)
        @events = @events.where("attempted_email LIKE ? OR metadata LIKE ?",
          "%#{params[:email]}%", "%#{params[:email]}%")
      end

      # Filter by date range
      if params[:start_date].present?
        begin
          start_date = Date.parse(params[:start_date])
          @events = @events.where("created_at >= ?", start_date.beginning_of_day)
        rescue ArgumentError
          # Invalid date, ignore filter
        end
      end

      if params[:end_date].present?
        begin
          end_date = Date.parse(params[:end_date])
          @events = @events.where("created_at <= ?", end_date.end_of_day)
        rescue ArgumentError
          # Invalid date, ignore filter
        end
      end

      # Quick time range filters
      if params[:time_range].present?
        start_time = case params[:time_range]
        when "last_hour"
          1.hour.ago
        when "last_24h"
          24.hours.ago
        when "last_7d"
          7.days.ago
        when "last_30d"
          30.days.ago
        end

        @events = @events.where("created_at >= ?", start_time) if start_time
      end

      # Filter by threat level
      if params[:threats_only] == "true"
        @events = @events.high_risk
      end

      # Search in metadata
      if params[:search].present?
        search_term = "%#{params[:search]}%"
        # Use database-agnostic approach for metadata search
        @events = if ActiveRecord::Base.connection.adapter_name == "PostgreSQL"
          @events.where(
            "ip_address LIKE ? OR user_agent LIKE ? OR attempted_email LIKE ? OR metadata::text LIKE ?",
            search_term, search_term, search_term, search_term
          )
        else
          # For SQLite and other databases, search in regular columns
          # SQLite's JSON support varies by version, so we'll search in standard columns
          @events.where(
            "ip_address LIKE ? OR user_agent LIKE ? OR attempted_email LIKE ? OR event_type LIKE ?",
            search_term, search_term, search_term, search_term
          )
        end
      end
    end

    def generate_csv(events)
      require "csv"

      CSV.generate(headers: true) do |csv|
        csv << ["ID", "Date/Time", "Event Type", "IP Address", "User", "Risk Score", "User Agent", "Details"]

        events.find_each do |event|
          csv << [
            event.id,
            event.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            event.event_type,
            event.ip_address,
            event.user&.try(:email) || event.attempted_email || "-",
            event.risk_score,
            event.user_agent,
            event.details || event.metadata&.dig("message") || "-"
          ]
        end
      end
    end
  end
end

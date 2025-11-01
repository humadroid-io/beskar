# frozen_string_literal: true

begin
  require 'maxminddb'
rescue LoadError
  # MaxMindDB gem not available
end

module Beskar
  module Services
    # Service for detecting geographic location from IP addresses
    #
    # This service provides IP-based geolocation capabilities for security analysis,
    # impossible travel detection, and geographic anomaly detection.
    #
    # Features:
    # - Efficient MaxMind database reading with singleton pattern
    # - Automatic caching with configurable TTL
    # - Private IP detection
    # - Impossible travel detection using Haversine formula
    #
    # @example Basic usage
    #   service = Beskar::Services::GeolocationService.new
    #   location = service.locate("203.0.113.1")
    #   # => {
    #   #   ip: "203.0.113.1",
    #   #   country: "United States",
    #   #   country_code: "US",
    #   #   city: "New York",
    #   #   latitude: 40.7128,
    #   #   longitude: -74.0060,
    #   #   timezone: "America/New_York"
    #   # }
    #
    class GeolocationService
      # Private/internal IP ranges that should not be geolocated
      PRIVATE_IP_RANGES = [
        IPAddr.new('10.0.0.0/8'),      # RFC 1918 - Private networks
        IPAddr.new('172.16.0.0/12'),   # RFC 1918 - Private networks
        IPAddr.new('192.168.0.0/16'),  # RFC 1918 - Private networks
        IPAddr.new('127.0.0.0/8'),     # Loopback
        IPAddr.new('169.254.0.0/16'),  # Link-local
        IPAddr.new('224.0.0.0/4'),     # Multicast
        IPAddr.new('::1/128'),         # IPv6 loopback
        IPAddr.new('fe80::/10'),       # IPv6 link-local
        IPAddr.new('fc00::/7')         # IPv6 unique local
      ].freeze

      # Cache TTL for geolocation results (4 hours)
      CACHE_TTL = 4.hours

      # Thread-safe reader for MaxMind City database
      @city_reader_mutex = Mutex.new
      @city_reader = nil

      class << self
        attr_reader :city_reader_mutex
        # Convenience method for one-off location lookup
        #
        # @param ip_address [String] The IP address to locate
        # @return [Hash] Location information
        def locate(ip_address)
          new.locate(ip_address)
        end

        # Check if an IP address is private/internal
        #
        # @param ip_address [String] The IP address to check
        # @return [Boolean] true if private/internal IP
        def private_ip?(ip_address)
          return true if ip_address.blank?

          begin
            ip = IPAddr.new(ip_address)
            PRIVATE_IP_RANGES.any? { |range| range.include?(ip) }
          rescue IPAddr::InvalidAddressError
            true # Treat invalid IPs as private
          end
        end

        # Calculate distance between two geographic points using Haversine formula
        #
        # @param lat1 [Float] Latitude of first point
        # @param lon1 [Float] Longitude of first point
        # @param lat2 [Float] Latitude of second point
        # @param lon2 [Float] Longitude of second point
        # @return [Float] Distance in kilometers
        def calculate_distance(lat1, lon1, lat2, lon2)
          return 0.0 if lat1.nil? || lon1.nil? || lat2.nil? || lon2.nil?

          # Convert degrees to radians
          lat1_rad = lat1 * Math::PI / 180
          lon1_rad = lon1 * Math::PI / 180
          lat2_rad = lat2 * Math::PI / 180
          lon2_rad = lon2 * Math::PI / 180

          # Haversine formula
          dlat = lat2_rad - lat1_rad
          dlon = lon2_rad - lon1_rad

          a = Math.sin(dlat/2)**2 + Math.cos(lat1_rad) * Math.cos(lat2_rad) * Math.sin(dlon/2)**2
          c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a))

          # Earth's radius in kilometers
          earth_radius = 6371.0
          earth_radius * c
        end
      end

      # Get or initialize the MaxMind City database reader
      # Uses thread-safe singleton pattern for efficient database access
      #
      # @return [MaxMindDB::Reader, nil] The reader instance or nil if not configured
      def self.city_reader
        return @city_reader if @city_reader
        return nil unless Beskar.configuration.maxmind_city_db_path
        return nil unless defined?(MaxMindDB)

        @city_reader_mutex.synchronize do
          return @city_reader if @city_reader

          db_path = Beskar.configuration.maxmind_city_db_path
          if File.exist?(db_path)
            @city_reader = MaxMindDB.new(db_path)
            Beskar::Logger.info("MaxMind City database loaded from #{db_path}", component: :GeolocationService)
          else
            Beskar::Logger.warn("MaxMind City database not found at #{db_path}", component: :GeolocationService)
          end
          @city_reader
        end
      rescue => e
        Beskar::Logger.error("Failed to load MaxMind City database: #{e.message}", component: :GeolocationService)
        nil
      end

      # Reset the database reader (useful for testing or reloading configuration)
      def self.reset_readers!
        @city_reader_mutex.synchronize { @city_reader = nil }
      end

      # Initialize the geolocation service
      #
      # @param provider [Symbol] The geolocation provider to use (:maxmind, :mock)
      def initialize(provider: nil)
        @provider = provider || Beskar.configuration.geolocation_provider
        @cache_key_prefix = "beskar:geolocation"
        @cache_ttl = Beskar.configuration.geolocation_cache_ttl
      end

      # Locate an IP address and return geographic information
      #
      # @param ip_address [String] The IP address to locate
      # @return [Hash] Location information with country, city, coordinates, etc.
      def locate(ip_address)
        if self.class.private_ip?(ip_address)
          result = private_ip_result(ip_address)
          result[:provider] = @provider
          return result
        end

        # Check cache first
        if cached_result = get_cached_location(ip_address)
          return cached_result
        end

        # Perform lookup based on provider
        case @provider
        when :maxmind
          result = lookup_maxmind(ip_address)
        when :ip2location
          result = lookup_ip2location(ip_address)
        else
          result = lookup_mock(ip_address)
        end

        # Cache the result
        cache_location(ip_address, result)

        result
      rescue => e
        Beskar::Logger.warn("Failed to locate IP #{ip_address}: #{e.message}", component: :GeolocationService)
        unknown_location(ip_address)
      end

      # Check if travel between two locations is impossible given the time difference
      #
      # @param location1 [Hash] First location with latitude/longitude
      # @param location2 [Hash] Second location with latitude/longitude
      # @param time_diff_seconds [Integer] Time difference in seconds
      # @param max_speed_kmh [Integer] Maximum realistic travel speed in km/h (default: 1000 for commercial flights)
      # @return [Boolean] true if travel is impossible
      def impossible_travel?(location1, location2, time_diff_seconds, max_speed_kmh: 1000)
        return false if location1.nil? || location2.nil?
        return false unless location1[:latitude] && location2[:latitude]

        distance_km = self.class.calculate_distance(
          location1[:latitude], location1[:longitude],
          location2[:latitude], location2[:longitude]
        )

        # Calculate maximum possible distance at given speed
        time_hours = time_diff_seconds / 3600.0
        max_distance_km = max_speed_kmh * time_hours

        distance_km > max_distance_km
      end

      # Calculate risk score based on geolocation factors
      #
      # @param ip_address [String] The IP address
      # @param previous_locations [Array<Hash>] Array of previous location hashes
      # @param time_since_last [Integer] Seconds since last login
      # @return [Integer] Risk score from 0 to 30
      def calculate_location_risk(ip_address, previous_locations = [], time_since_last = nil)
        current_location = locate(ip_address)
        risk = 0

        # Private/unknown IPs have moderate risk
        return 10 if current_location[:country] == "Unknown" || current_location[:country] == "Private"

        # Check for impossible travel if we have previous locations
        if previous_locations.any? && time_since_last
          previous_locations.each do |prev_location|
            if impossible_travel?(current_location, prev_location, time_since_last)
              risk += 25
              break
            end
          end
        end

        # Country change adds some risk
        if previous_locations.any?
          recent_countries = previous_locations.map { |loc| loc[:country] }.uniq
          risk += 10 unless recent_countries.include?(current_location[:country])
        end

        # Known high-risk countries (this would be configurable in production)
        high_risk_countries = ['Unknown']
        risk += 15 if high_risk_countries.include?(current_location[:country])

        [risk, 30].min # Cap at 30 to leave room for other risk factors
      end

      private

      # Return result for private/internal IP addresses
      #
      # @param ip_address [String] The private IP address
      # @return [Hash] Location information for private IP
      def private_ip_result(ip_address)
        {
          ip: ip_address,
          country: "Private",
          country_code: nil,
          city: "Local Network",
          latitude: nil,
          longitude: nil,
          timezone: nil,
          provider: @provider,
          private_ip: true
        }
      end

      # Return result for unknown/unlocatable IP addresses
      #
      # @param ip_address [String] The IP address
      # @return [Hash] Unknown location information
      def unknown_location(ip_address)
        {
          ip: ip_address,
          country: "Unknown",
          country_code: nil,
          city: "Unknown",
          latitude: nil,
          longitude: nil,
          timezone: nil,
          provider: @provider,
          private_ip: false
        }
      end

      # Mock geolocation lookup for testing/development
      #
      # @param ip_address [String] The IP address
      # @return [Hash] Mock location information
      def lookup_mock(ip_address)
        # Generate consistent mock data based on IP
        country_codes = ['US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU']
        cities = ['New York', 'Toronto', 'London', 'Berlin', 'Paris', 'Tokyo', 'Sydney']

        index = ip_address.bytes.sum % country_codes.length

        {
          ip: ip_address,
          country: case country_codes[index]
                   when 'US' then 'United States'
                   when 'CA' then 'Canada'
                   when 'GB' then 'United Kingdom'
                   when 'DE' then 'Germany'
                   when 'FR' then 'France'
                   when 'JP' then 'Japan'
                   when 'AU' then 'Australia'
                   end,
          country_code: country_codes[index],
          city: cities[index],
          latitude: (40.0 + (index * 10)) % 90,
          longitude: (-74.0 + (index * 15)) % 180,
          timezone: "UTC#{index > 3 ? '+' : '-'}#{index + 1}",
          provider: @provider,
          private_ip: false
        }
      end

      # Lookup using MaxMind GeoIP2 database
      #
      # @param ip_address [String] The IP address
      # @return [Hash] Location information from MaxMind
      def lookup_maxmind(ip_address)
        result = { ip: ip_address, provider: @provider, private_ip: false }

        # Lookup city/location data
        if city_reader = self.class.city_reader
          begin
            city_data = city_reader.lookup(ip_address)
            if city_data&.found?
              city_hash = city_data.to_hash
              result.merge!(
                country: city_hash.dig("country", "names", "en") || "Unknown",
                country_code: city_hash.dig("country", "iso_code"),
                city: city_hash.dig("city", "names", "en") || "Unknown",
                latitude: city_hash.dig("location", "latitude"),
                longitude: city_hash.dig("location", "longitude"),
                timezone: city_hash.dig("location", "time_zone"),
                postal_code: city_hash.dig("postal", "code"),
                subdivision: city_hash.dig("subdivisions", 0, "names", "en"),
                subdivision_code: city_hash.dig("subdivisions", 0, "iso_code")
              )
            else
              result.merge!(unknown_location(ip_address).except(:ip, :provider, :private_ip))
            end
          rescue => e
            Beskar::Logger.warn("MaxMind City lookup failed for #{ip_address}: #{e.message}", component: :GeolocationService)
            result.merge!(unknown_location(ip_address).except(:ip, :provider, :private_ip))
          end
        else
          # No city database configured, return basic unknown location
          result.merge!(unknown_location(ip_address).except(:ip, :provider, :private_ip))
        end

        result
      rescue => e
        Beskar::Logger.error("MaxMind lookup failed for #{ip_address}: #{e.message}", component: :GeolocationService)
        unknown_location(ip_address)
      end

      # Lookup using IP2Location database
      #
      # @param ip_address [String] The IP address
      # @return [Hash] Location information from IP2Location
      def lookup_ip2location(ip_address)
        # This would integrate with IP2Location in production
        # For now, return unknown result
        result = unknown_location(ip_address)
        result[:provider] = @provider
        result
      end

      # Get cached location result
      #
      # @param ip_address [String] The IP address
      # @return [Hash, nil] Cached location or nil
      def get_cached_location(ip_address)
        cache_key = "#{@cache_key_prefix}:#{ip_address}"
        Rails.cache.read(cache_key)
      rescue => e
        Beskar::Logger.debug("Cache read failed: #{e.message}", component: :GeolocationService)
        nil
      end

      # Cache location result
      #
      # @param ip_address [String] The IP address
      # @param result [Hash] The location result to cache
      def cache_location(ip_address, result)
        cache_key = "#{@cache_key_prefix}:#{ip_address}"
        Rails.cache.write(cache_key, result, expires_in: @cache_ttl)
      rescue => e
        Beskar::Logger.debug("Cache write failed: #{e.message}", component: :GeolocationService)
      end
    end
  end
end

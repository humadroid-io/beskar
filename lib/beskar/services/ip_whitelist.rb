require 'ipaddr'

module Beskar
  module Services
    class IpWhitelist
      class << self
        # Check if an IP address is whitelisted
        def whitelisted?(ip_address)
          return false if ip_address.blank?
          return false unless whitelist_entries.any?

          ip = parse_ip(ip_address)
          return false unless ip

          whitelist_entries.any? do |entry|
            match_entry?(ip, entry)
          end
        rescue IPAddr::InvalidAddressError, ArgumentError => e
          Beskar::Logger.warn("Invalid IP address: #{ip_address} - #{e.message}", component: :IpWhitelist)
          false
        end

        # Get whitelist entries from configuration
        def whitelist_entries
          @whitelist_entries ||= begin
            entries = Beskar.configuration.ip_whitelist || []
            # Ensure it's an array
            entries = [entries] unless entries.is_a?(Array)
            entries.compact
          end
        end

        # Clear cached whitelist (useful when config changes)
        def clear_cache!
          @whitelist_entries = nil
          @parsed_entries = nil
        end

        # Validate whitelist configuration
        def validate_configuration!
          errors = []
          
          whitelist_entries.each_with_index do |entry, index|
            begin
              parse_entry(entry)
            rescue IPAddr::InvalidAddressError, ArgumentError => e
              errors << "Entry #{index} (#{entry}): #{e.message}"
            end
          end

          if errors.any?
            raise ConfigurationError, "Invalid IP whitelist configuration:\n#{errors.join("\n")}"
          end

          true
        end

        private

        # Parse IP address string to IPAddr object
        def parse_ip(ip_string)
          IPAddr.new(ip_string.to_s.strip)
        rescue IPAddr::InvalidAddressError
          nil
        end

        # Parse whitelist entry (can be single IP or CIDR notation)
        def parse_entry(entry)
          return nil if entry.blank?
          
          entry_str = entry.to_s.strip
          
          # Check if it's CIDR notation
          if entry_str.include?('/')
            IPAddr.new(entry_str)
          else
            # Single IP address
            IPAddr.new(entry_str)
          end
        end

        # Check if IP matches whitelist entry
        def match_entry?(ip, entry)
          parsed_entry = parsed_entries[entry]
          return false unless parsed_entry

          # IPAddr#include? handles both single IPs and CIDR ranges
          parsed_entry.include?(ip)
        rescue IPAddr::InvalidAddressError, ArgumentError
          false
        end

        # Cache parsed entries for performance
        def parsed_entries
          @parsed_entries ||= begin
            entries = {}
            whitelist_entries.each do |entry|
              begin
                entries[entry] = parse_entry(entry)
              rescue IPAddr::InvalidAddressError, ArgumentError => e
                Beskar::Logger.warn("Skipping invalid entry: #{entry} - #{e.message}", component: :IpWhitelist)
              end
            end
            entries
          end
        end
      end

      # Error class for configuration issues
      class ConfigurationError < StandardError; end
    end
  end
end

module Beskar
  module Models
    # Main SecurityTrackable module - delegates to Devise-specific implementation
    # for backward compatibility with existing Devise integrations
    #
    # This is now a thin wrapper around the modular implementation:
    # - SecurityTrackableGeneric: Shared functionality for all auth systems
    # - SecurityTrackableDevise: Devise/Warden specific (included by default here)
    # - SecurityTrackableAuthenticable: Rails 8 has_secure_password specific
    #
    # Usage:
    #   For Devise models:
    #     include Beskar::Models::SecurityTrackable  # (this module)
    #   For Rails 8 auth models:
    #     include Beskar::Models::SecurityTrackableAuthenticable
    module SecurityTrackable
      extend ActiveSupport::Concern

      included do
        # Include Devise-specific tracking by default for backward compatibility
        include Beskar::Models::SecurityTrackableDevise
      end
    end
  end
end

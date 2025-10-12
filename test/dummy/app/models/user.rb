class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy

  normalizes :email_address, with: ->(e) { e.strip.downcase }

  # Include Beskar security tracking for Rails 8 authentication
  include Beskar::Models::SecurityTrackableAuthenticable
end

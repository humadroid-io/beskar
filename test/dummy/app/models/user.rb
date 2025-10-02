class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy

  normalizes :email_address, with: ->(e) { e.strip.downcase }

  # Include Beskar security tracking
  include Beskar::Models::SecurityTrackable
end

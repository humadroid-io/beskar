FactoryBot.define do
  # Rails 8 authentication User model (has_secure_password)
  factory :user, class: "User" do
    sequence(:email_address) { |n| "user#{n}@example.com" }
    password { "password123" }
    password_confirmation { "password123" }
  end
end

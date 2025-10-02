class ApplicationController < ActionController::Base
  # Authentication is included per-controller basis to allow both
  # Devise and Rails 8 authentication to coexist
  # Controllers can include Authentication or use devise's authenticate_* methods
end

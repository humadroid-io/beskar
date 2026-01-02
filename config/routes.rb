Beskar::Engine.routes.draw do
  # Root route - dashboard
  root to: "dashboard#index"

  # Dashboard
  get "dashboard", to: "dashboard#index", as: :dashboard

  # Security Events
  resources :security_events, only: [:index, :show] do
    collection do
      get "export"
    end
  end

  # Banned IPs
  resources :banned_ips do
    member do
      post "extend"
    end

    collection do
      post "bulk_action"
      get "export"
    end
  end

  # API endpoints (optional, for future AJAX calls)
  namespace :api do
    namespace :v1 do
      resources :security_events, only: [:index, :show] do
        collection do
          get "stats"
        end
      end

      resources :banned_ips, only: [:index, :show, :create, :destroy] do
        member do
          post "extend"
        end
      end
    end
  end
end

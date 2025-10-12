Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  devise_for :devise_users
  mount Beskar::Engine => "/beskar"

  get "devise_restricted" => "welcome#devise_restricted"
  get "user_restricted" => "welcome#user_restricted"
  root to: "welcome#index"
end

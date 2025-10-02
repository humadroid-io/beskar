Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  devise_for :devise_users
  mount Beskar::Engine => "/beskar"

  get "restricted" => "welcome#restricted"
  root to: "welcome#index"
end

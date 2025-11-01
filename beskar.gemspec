require_relative "lib/beskar/version"

Gem::Specification.new do |spec|
  spec.name = "beskar"
  spec.version = Beskar::VERSION
  spec.authors = ["Maciej Litwiniuk"]
  spec.email = ["maciej@litwiniuk.net"]
  spec.homepage = "https://humadroid.io/beskar"
  spec.summary = "An all-in-one security engine for Rails providing WAF, bot detection, and account takeover prevention."
  spec.description = "Rails Security Shield is a comprehensive, Rails-native security engine designed to provide multi-layered protection for modern web applications. It actively defends against common threats by integrating a powerful Web Application Firewall (WAF) to block attacks like SQLi and XSS, an advanced bot detection system using JavaScript challenges and honeypots, and robust account takeover prevention to stop brute-force and credential stuffing attacks.

Built as a mountable Rails Engine, it leverages core framework features like ActiveJob and Rails.cache to ensure high performance and minimal external dependencies. It includes a real-time dashboard for monitoring security events, giving you immediate insight into the threats your application faces. Drop it in, configure it, and get enterprise-grade security that feels like a natural extension of Rails."
  spec.license = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the "allowed_push_host"
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  # spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/humadroid-io/beskar"
  spec.metadata["changelog_uri"] = "https://github.com/humadroid-io/beskar/blob/master/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md", "CHANGELOG.md"]
  end

  spec.add_dependency "rails", ">= 8.0.0"

  # Optional: MaxMind DB reader for GeoIP functionality
  # Users need to provide their own GeoIP database due to licensing
  spec.add_dependency "maxminddb", "~> 0.1"

  spec.add_development_dependency "debug"
  spec.add_development_dependency "devise"
  spec.add_development_dependency "factory_bot_rails"
  spec.add_development_dependency "mocha"
  spec.add_development_dependency "ostruct"
end

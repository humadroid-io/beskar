# Changelog

All notable changes to Beskar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ⚠️ BREAKING CHANGES

- **Monitor-only mode refactored to top-level configuration**
  - `config.waf[:monitor_only]` has been **removed**
  - Use `config.monitor_only = true/false` at the configuration root level instead
  - The method `Beskar.configuration.waf_monitor_only?` has been **removed**
  - Use `Beskar.configuration.monitor_only?` instead
  - See [BREAKING_CHANGES.md](BREAKING_CHANGES.md) for detailed migration guide

### Added

- Ban records (`Beskar::BannedIp`) are now created even in monitor-only mode
  - Provides full visibility into what would be blocked
  - Allows querying `Beskar::BannedIp.active` to see potential blocks
  - Makes verification and testing much more reliable
- Global monitor-only mode affecting all blocking features (WAF, rate limiting, IP bans)
- **Centralized logging system** (`Beskar::Logger`)
  - Consistent log formatting with automatic `[Beskar]` or `[Beskar::Component]` prefixes
  - Component name aliasing for cleaner output (e.g., `Beskar::Services::Waf` → `WAF`)
  - Configurable log levels and output backends
  - Include module support for automatic component detection in classes
  - Single point of configuration for all logging

### Changed

- Monitor-only mode is now a system-wide concept rather than WAF-specific
- Ban records are created but not enforced when `monitor_only = true`
- Security events include `monitor_only_mode` metadata flag
- All blocking decisions (WAF, rate limiting, authentication abuse) respect global monitor-only setting
- Improved logging with clear "MONITOR-ONLY" indicators
- Better separation of ban creation from ban enforcement
- All internal logging now uses `Beskar::Logger` instead of direct `Rails.logger` calls
- Log messages no longer require manual prefix formatting

### Fixed

- Monitor-only mode now provides actual data for verification (ban records exist)
- Consistent behavior across all security features
- Clearer semantics for what monitor-only mode means

### Documentation

- Updated README with new configuration structure
- Enhanced MONITOR_ONLY_MODE.md with examples of querying ban records
- Added migration guide in BREAKING_CHANGES.md
- Created PROJECT_DOCUMENTATION.md for development reference


### Versioning Policy

- **Major version (X.0.0)**: Breaking changes that require code changes
- **Minor version (0.X.0)**: New features, backward compatible
- **Patch version (0.0.X)**: Bug fixes and minor improvements

### Upgrade Guide

When upgrading between versions with breaking changes:

1. Read the [BREAKING_CHANGES.md](BREAKING_CHANGES.md) file
2. Update your configuration according to the migration guide
3. Run any new migrations: `rails db:migrate`
4. Test in development/staging before deploying to production
5. Start with `monitor_only = true` to verify behavior

### Support

- GitHub Issues: https://github.com/humadroid-io/beskar/issues
- Documentation: https://humadroid.io/beskar

---

[Unreleased]: https://github.com/humadroid-io/beskar/compare/v0.0.2...HEAD

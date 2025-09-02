# CHANGELOG.md – SVLJmTLSClientAuthenticatorModule

All notable changes to this module are documented in this file.

## [v0.4] – 2025-09-01
### Added
- First public release of **SVLJmTLSClientAuthenticatorModule**.
- Provides hardened `HttpClient` factory with mutual TLS (mTLS) support.
- Client certificate loading:
  - From PFX file (password via environment variable)
  - From Windows Certificate Store (thumbprint)
- Strict fail-closed server certificate validation:
  - Enforces certificate validity (`NotBefore` / `NotAfter`)
  - Supports revocation checking (`Online`, `Offline`, `NoCheck`)
  - Supports custom CA bundle (PEM)
  - Optional Issuer CN match
  - Optional Thumbprint match
- TLS policy enforcement (minimum TLS 1.2 or 1.3).
- Configuration via `appSettings` in `web.config` or `app.config`

# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this module, **please report it responsibly**:

- **Do not create public GitHub issues**
- Instead, contact:  
  - 📧 security@svlj.net

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected environment (.NET version, OS, IIS config)
- Expected vs actual behavior
- CVSS score if known (optional)

We aim to respond within **5 business days** and will work with you to verify, fix and disclose responsibly.

---

## Security Best Practices for Users

To protect your deployment:

- Only include **trusted CA certificates** in `ca-bundle.pem`
- Protect `web.config` and the `bin/` folder with **NTFS ACLs**
- Use TLS 1.2 or higher only

---

## Known Limitations

- The module uses .NET Framework `X509Chain` which may not support all custom PKI environments.
- Revocation checks rely on CRL distribution points being reachable from the server.

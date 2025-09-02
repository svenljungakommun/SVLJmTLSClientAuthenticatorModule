# RISK ANALYSIS – SVLJmTLSClientAuthenticatorModule

A structured threat and mitigation analysis

## 📚 Table of Contents

* [Introduction](#-introduction)
* [Protected Assets](#-protected-assets)
* [Identified Risks](#-identified-risks)
* [Module Assessment (Post-Mitigation)](#-module-assessment-post-mitigation)
* [Recommended Actions](#-recommended-actions)

---

## 🧩 Introduction

The module protects outbound connections by enforcing strict mutual TLS (mTLS) when creating `HttpClient` instances. It loads client certificates from PFX or Windows Certificate Store, validates server certificates against trusted Certificate Authorities (CAs), checks validity periods and trust chains, and blocks connections if validation fails.

This ensures that client applications only connect to authorized servers, maintaining Zero Trust principles for critical municipal and infrastructure systems.

---

## 🔐 Protected Assets

| Asset                          | Type          | Protection Value |
| ------------------------------ | ------------- | ---------------- |
| Outbound API connection        | Service       | High             |
| Client certificate (PFX/Store) | Credential    | High             |
| CA bundle (trusted issuers)    | Configuration | High             |
| Application secrets (env vars) | Configuration | High             |

---

## ⚠️ Identified Risks

| Risk ID | Threat                                     | Consequence                           | Likelihood | Risk Level | Comment                                                    |
| ------: | ------------------------------------------ | ------------------------------------- | ---------- | ---------- | ---------------------------------------------------------- |
|      R1 | Faulty CRL/OCSP handling                   | Invalid server certificates accepted  | Medium     | High       | Online revocation depends on external availability         |
|      R2 | Incorrect or tampered CA bundle            | Broken trust chain                    | Low        | High       | Misconfiguration or tampering undermines validation        |
|      R3 | Missing time validation                    | Expired/future certs accepted         | High       | High       | Mitigated in v0.4 with NotBefore/NotAfter enforcement      |
|      R4 | Weak signature algorithm on server cert    | Acceptance of weak server identities  | Low        | Medium     | Not explicitly checked in this version                     |
|      R5 | Disabled StrictServerValidation flag       | Validation bypassed                   | Low        | High       | Should remain `true` in production                         |
|      R6 | No detailed logging of validation failures | Hard to trace why a connection failed | Medium     | Medium     | Module is fail-closed but silent; relies on app-level logs |
|      R7 | Thumbprint or IssuerCN misconfiguration    | Wrong server trusted                  | Medium     | Medium     | Requires careful config management                         |
|      R8 | PFX password leak (via env var)            | Unauthorized client certificate use   | Low        | High       | Mitigated by secure env handling                           |

---

## 🧪 Module Assessment (Post-Mitigation)

| Protection Feature                | Status  | Comment                                        |
| --------------------------------- | ------- | ---------------------------------------------- |
| TLS enforcement                   | ✅ OK    | Enforces TLS 1.2 or higher                     |
| Client certificate loading        | ✅ OK    | From PFX or Windows Store                      |
| CA bundle validation              | ✅ OK    | If configured, strict `CustomRootTrust`        |
| System trust fallback             | ✅ OK    | Used if no CABundle provided                   |
| Issuer CN matching                | ✅ OK    | Optional, exact string match                   |
| Thumbprint matching               | ✅ OK    | Optional, exact binary match                   |
| Validity period (NotBefore/After) | ✅ OK    | Always enforced                                |
| Revocation checking               | ⚠️ WARN | Online-only; dependent on network reachability |
| Logging                           | ⚠️ WARN | No built-in SIEM/SOC integration               |
| Config validation                 | 🛈 INFO | Relies on correct `appSettings` values         |
| Physical protection class         | 🛈 INFO | Managed by runtime environment (not in scope)  |

---

## ✅ Recommended Actions

| Recommendation                                 | Priority | Justification                               |
| ---------------------------------------------- | -------- | ------------------------------------------- |
| Implement CRL/OCSP caching or mirroring        | Medium   | Mitigates dependency on external revocation |
| Add structured logging for validation failures | Medium   | Improves monitoring and troubleshooting     |
| Enforce `StrictServerValidation=true` in prod  | High     | Prevents accidental bypass of checks        |
| Consider algorithm/EKU validation in future    | Low      | Strengthens assurance against weak certs    |
| Validate configuration at startup (fail-fast)  | Low      | Prevents runtime surprises from misconfig   |

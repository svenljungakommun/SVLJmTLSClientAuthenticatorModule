# SVLJmTLSClientAuthenticatorModule v0.4

**Mutual TLS (mTLS) HttpClient factory for .NET applications**  
Maintainer: Svenljunga kommun  

---

## Overview

`SVLJmTLSClientAuthenticatorModule` is a .NET component that provides a hardened `HttpClient` with mutual TLS (mTLS) support for outbound HTTPS connections.

It loads client X.509 certificates from PFX files or the Windows Certificate Store, and enforces strict, fail-closed validation of server certificates. This includes validity period, revocation checks, CA bundle verification, and optional Issuer CN / Thumbprint matching. Built for secure municipal and public sector infrastructure in Zero Trust architectures.

This module serves as the **client-side counterpart** to [SVLJmTLSClientValidatorModule](https://github.com/svenljungakommun/SVLJmTLSClientValidatorModule), ensuring secure two-way mTLS validation with Zero Trust principles.

**🔗 SVLJmTLSClientValidator family**  
The SVLJmTLSClientValidator components are available across platforms, providing consistent fail-closed mTLS enforcement:  

 [`SVLJmTLSClientValidatorModule`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorModule) – .NET `IHttpModule` for IIS (server-side)  
 [`SVLJmTLSClientValidatorFilter`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorFilter) – Java Servlet Filter for Tomcat  
 [`SVLJmTLSClientValidatorLUA`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorLUA) – `mod_lua` implementation for Apache2  
 `SVLJmTLSClientAuthenticatorModule` – .NET `HttpClient` factory for outbound calls  

---

## Features

* 🔐 Client certificate support:

  * Load from **PFX file** (password via environment variable)
  * Load from **Windows Certificate Store** (thumbprint-based)
* ✅ Server certificate validation (fail-closed):

  * Enforces NotBefore / NotAfter validity
  * Certificate chain validation against PEM CA bundle or system trust
  * Revocation checking (`Online`, `Offline`, `NoCheck`)
  * Optional Issuer CN match
  * Optional server certificate thumbprint match
* ⚙️ Configuration via `appSettings` in `web.config` or `app.config`
* 🚫 Fail-closed design: any failed check aborts the connection

---

## Compliance Alignment

This module supports security controls required by:

* **NIS2 Directive**
* **ISO/IEC 27001 & 27002**
* **GDPR (Art. 32 – Security of processing)**
* **CIS Benchmarks**
* **STIGs (US DoD)**

---

## Compatibility

- Supported runtimes:
  - .NET Framework 4.8
  - .NET 6
  - .NET 7
  - .NET 8

- Supported platforms:
  - Windows

---

## Directory Structure

```
/project-root
├── bin
│   └── SVLJ.Security.dll
├── web.config|app.config
└── certs
    └── ca-bundle.pem
```

---

## Example Configuration (`web.config` and `app.config`)

```xml
<configuration>
  <appSettings>
    <!-- Client certificate -->
    <!-- Pfx | Store (recommended)--> 
    <add key="SVLJ_Mode" value="Store"/>
    <add key="SVLJ_PfxPath" value="C:\certs\client.pfx"/>
    <add key="SVLJ_PfxPasswordEnv" value="PFX_PASSWORD"/>
    <add key="SVLJ_StoreLocation" value="CurrentUser"/>
    <add key="SVLJ_StoreName" value="My"/>
    <add key="SVLJ_Thumbprint" value=""/>
    <add key="SVLJ_TimeoutSeconds" value="30"/>

    <!-- Server validation -->
    <add key="SVLJ_RevocationMode" value="Online"/> <!-- Online | Offline | NoCheck -->
    <add key="SVLJ_StrictServerValidation" value="true"/>
    <add key="SVLJ_MinTls" value="1.2"/>

    <!-- Optional policies -->
    <add key="SVLJ_ServerIssuerCN" value=""/>
    <add key="SVLJ_ServerThumbprint" value=""/>
    <add key="SVLJ_CABundlePath" value="C:\certs\ca-bundle.pem"/>
  </appSettings>
</configuration>
```

---

## Example Usage

```csharp
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using SVLJ.Security;

class Program
{
    static async Task Main()
    {
        var client = SVLJmTLSClientAuthenticatorModule.FromConfig();
        var response = await client.GetAsync("https://secure-api.example.com/data");
        Console.WriteLine(await response.Content.ReadAsStringAsync());
    }
}
```

```csharp
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using SVLJ.Security;

class Program
{
    static async Task Main()
    {
        var client = SVLJmTLSClientAuthenticatorModule.FromConfig();

        // Add OAuth2 Bearer token
        string token = Environment.GetEnvironmentVariable("OAUTH_BEARER_TOKEN");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("https://secure-api.example.com/data");
        Console.WriteLine(await response.Content.ReadAsStringAsync());
    }
}
```

---

## Validation Flow

1. Server certificate must be present
2. Check validity dates (`NotBefore` / `NotAfter`)
3. If CA bundle configured: validate chain against custom trust
4. Otherwise: validate via system trust (`SslPolicyErrors == None`)
5. If configured: enforce Issuer CN
6. If configured: enforce server Thumbprint
7. If any check fails → connection aborts (fail-closed)

---

## Error Handling

This module is fail-closed: it does **not** provide “reason codes” or partial acceptance.
Connections are either **fully validated** or **rejected**.


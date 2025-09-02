using System;
using System.Configuration;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SVLJ.Security
{
    /// <summary>
    /// SVLJ.Security – Namespace for certificate-based security infrastructure in .NET applications.
    ///
    /// This namespace defines components for enforcing secure communication using X.509 certificates and mutual TLS (mTLS),
    /// focusing on strong client authentication, server trust validation, and Zero Trust enforcement for outbound HTTPS flows.
    ///
    /// It is intended for use in high-assurance environments such as municipal, governmental, and critical infrastructure systems,
    /// where precise control over certificate selection, server validation, and policy enforcement is essential.
    ///
    /// Core responsibilities:
    /// - Encapsulating reusable logic for secure HttpClient creation with client certificates
    /// - Managing certificate authority bundles, revocation modes, and issuer/subject constraints
    /// - Enforcing mTLS validation for outbound .NET applications and service integrations
    /// - Supporting configuration via `appSettings` in `web.config` or `app.config`
    ///
    /// The namespace enforces a "fail-closed" posture and is designed for extensibility, auditability, and policy compliance.
    ///
    /// Typical deployment targets include PKI-protected APIs, administrative system integrations, and inter-domain
    /// communication across segmented SDN architectures.
    ///
    /// Maintainer: Svenljunga kommun
    /// </summary>
    public static class SVLJmTLSClientAuthenticatorModule
    {
        private sealed class AuthenticatorOptions
        {
            // Client settings
            public string ClientMode { get; init; } = "Pfx"; // Pfx | Store
            public string? ClientPfxPath { get; init; }
            public string? ClientPfxPasswordEnv { get; init; }
            public string ClientStoreLocation { get; init; } = "CurrentUser";
            public string ClientStoreName { get; init; } = "My";
            public string? ClientThumbprint { get; init; }
            public int ClientTimeoutSeconds { get; init; } = 30;

            // Server validation settings
            public string RevocationMode { get; init; } = "Online";   // Online | Offline | NoCheck
            public bool StrictServerValidation { get; init; } = true;
            public string ServerMinTls { get; init; } = "1.2";        // 1.2 | 1.3
            public string? ServerIssuerCN { get; init; }
            public string? ServerThumbprint { get; init; }
            public string? CaBundlePath { get; init; }
        }

        /// <summary>
        /// Reads configuration from AppSettings and builds
        /// </summary>
        private static AuthenticatorOptions LoadOptions()
        {
            return new AuthenticatorOptions
            {
                ClientMode = ConfigurationManager.AppSettings["SVLJ_Mode"] ?? "Pfx",
                ClientPfxPath = ConfigurationManager.AppSettings["SVLJ_PfxPath"],
                ClientPfxPasswordEnv = ConfigurationManager.AppSettings["SVLJ_PfxPasswordEnv"],
                ClientStoreLocation = ConfigurationManager.AppSettings["SVLJ_StoreLocation"] ?? "CurrentUser",
                ClientStoreName = ConfigurationManager.AppSettings["SVLJ_StoreName"] ?? "My",
                ClientThumbprint = ConfigurationManager.AppSettings["SVLJ_Thumbprint"],
                ClientTimeoutSeconds = ParseInt(ConfigurationManager.AppSettings["SVLJ_TimeoutSeconds"], 30),

                RevocationMode = ConfigurationManager.AppSettings["SVLJ_RevocationMode"] ?? "Online",
                StrictServerValidation = ParseBool(ConfigurationManager.AppSettings["SVLJ_StrictServerValidation"], true),
                ServerMinTls = ConfigurationManager.AppSettings["SVLJ_MinTls"] ?? "1.2",
                ServerIssuerCN = ConfigurationManager.AppSettings["SVLJ_ServerIssuerCN"],
                ServerThumbprint = ConfigurationManager.AppSettings["SVLJ_ServerThumbprint"],
                CaBundlePath = ConfigurationManager.AppSettings["SVLJ_CABundlePath"]
            };
        }

        /// <summary>
        /// Creates a hardened HttpClient for mTLS, configured via AppSettings.
        /// </summary>
        public static HttpClient FromConfig()
        {
            var opt = LoadOptions();

            var handler = new SocketsHttpHandler
            {
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = ToProtocols(opt.ServerMinTls),
                    CertificateRevocationCheckMode = ToRevocationMode(opt.RevocationMode),
                    RemoteCertificateValidationCallback = (s, cert, chain, errors) =>
                        ValidateServer(cert, chain, errors, opt)
                }
            };

            var cert = LoadClientCert(opt);
            if (cert is not null)
                handler.SslOptions.ClientCertificates = new X509CertificateCollection { cert };

            return new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(opt.ClientTimeoutSeconds)
            };
        }

        /// <summary>
        /// Strict fail-closed server certificate validation.
        /// Returns true only if all checks succeed, otherwise false.
        /// </summary>
        private static bool ValidateServer(X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors, AuthenticatorOptions opt)
        {
            if (!opt.StrictServerValidation) return true;
            if (cert is null) return false;

            var c2 = cert as X509Certificate2 ?? new X509Certificate2(cert);

            // 1. Validity check
            var now = DateTime.UtcNow;
            if (now < c2.NotBefore.ToUniversalTime()) return false;
            if (now > c2.NotAfter.ToUniversalTime()) return false;

            // 2. CABundle validation (if provided)
            if (!string.IsNullOrWhiteSpace(opt.CaBundlePath) && File.Exists(opt.CaBundlePath))
            {
                var bundle = LoadCaBundle(opt.CaBundlePath);
                using var customChain = new X509Chain
                {
                    ChainPolicy =
                    {
                        RevocationMode = ToRevocationMode(opt.RevocationMode),
                        TrustMode = X509ChainTrustMode.CustomRootTrust
                    }
                };

                foreach (var ca in bundle)
                {
                    if (ca.Subject == ca.Issuer)
                        customChain.ChainPolicy.CustomTrustStore.Add(ca);
                    else
                        customChain.ChainPolicy.ExtraStore.Add(ca);
                }

                if (!customChain.Build(c2))
                    return false;
            }
            else if (errors != SslPolicyErrors.None)
            {
                // 3. Fallback to system trust
                return false;
            }

            // 4. Issuer CN (optional)
            if (!string.IsNullOrWhiteSpace(opt.ServerIssuerCN) &&
                !c2.Issuer.Contains($"CN={opt.ServerIssuerCN}", StringComparison.OrdinalIgnoreCase))
                return false;

            // 5. Server thumbprint (optional)
            if (!string.IsNullOrWhiteSpace(opt.ServerThumbprint))
            {
                var norm = NormalizeThumbprint(opt.ServerThumbprint);
                var actual = NormalizeThumbprint(c2.Thumbprint);
                if (!actual.Equals(norm, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            // All checks passed
            return true;
        }

        /// <summary>
        /// Loads client certificate from PFX or Store depending on configuration.
        /// </summary>
        private static X509Certificate2? LoadClientCert(AuthenticatorOptions opt)
        {
            return opt.ClientMode.Equals("Pfx", StringComparison.OrdinalIgnoreCase)
                ? LoadFromPfx(opt.ClientPfxPath, opt.ClientPfxPasswordEnv)
                : LoadFromStore(opt.ClientStoreLocation, opt.ClientStoreName, opt.ClientThumbprint);
        }

        /// <summary>
        /// Loads client certificate from a PFX file.
        /// </summary>
        private static X509Certificate2? LoadFromPfx(string? path, string? passwordEnv)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            var pwd = string.IsNullOrWhiteSpace(passwordEnv) ? null : Environment.GetEnvironmentVariable(passwordEnv);
            return new X509Certificate2(path, pwd,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.MachineKeySet);
        }

        /// <summary>
        /// Loads client certificate from Windows certificate store.
        /// </summary>
        private static X509Certificate2? LoadFromStore(string? loc, string? name, string? thumb)
        {
            if (string.IsNullOrWhiteSpace(thumb)) return null;
            var location = loc?.Equals("LocalMachine", StringComparison.OrdinalIgnoreCase) == true
                ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
            var storeName = Enum.TryParse<StoreName>(name, true, out var sn) ? sn : StoreName.My;

            using var store = new X509Store(storeName, location);
            store.Open(OpenFlags.ReadOnly);

            var norm = NormalizeThumbprint(thumb);
            foreach (var c in store.Certificates)
                if (NormalizeThumbprint(c.Thumbprint) == norm && c.HasPrivateKey)
                    return c;
            return null;
        }

        /// <summary>
        /// Loads a CA bundle (PEM file) into an <see cref="X509Certificate2Collection"/>.
        /// </summary>
        private static X509Certificate2Collection LoadCaBundle(string path)
        {
            var coll = new X509Certificate2Collection();
            var pem = File.ReadAllText(path);
            var parts = pem.Split("-----END CERTIFICATE-----", StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var idx = part.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal);
                if (idx < 0) continue;
                var b64 = part[(idx + "-----BEGIN CERTIFICATE-----".Length)..];
                var raw = Convert.FromBase64String(b64.Replace("\r", "").Replace("\n", "").Trim());
                coll.Add(new X509Certificate2(raw));
            }
            return coll;
        }

        private static string NormalizeThumbprint(string? s) =>
            string.IsNullOrWhiteSpace(s) ? string.Empty :
            s.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();

        private static bool ParseBool(string? v, bool dflt) =>
            v is null ? dflt : v.Equals("true", StringComparison.OrdinalIgnoreCase);

        private static int ParseInt(string? v, int dflt) =>
            int.TryParse(v, out var i) ? i : dflt;

        private static SslProtocols ToProtocols(string min) =>
            min.Equals("1.3", StringComparison.OrdinalIgnoreCase)
                ? SslProtocols.Tls13 | SslProtocols.Tls12
                : SslProtocols.Tls12;

        private static X509RevocationMode ToRevocationMode(string mode) =>
            mode.Equals("NoCheck", StringComparison.OrdinalIgnoreCase) ? X509RevocationMode.NoCheck :
            mode.Equals("Offline", StringComparison.OrdinalIgnoreCase) ? X509RevocationMode.Offline :
            X509RevocationMode.Online;
    }
}

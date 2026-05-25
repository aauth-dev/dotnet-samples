using System.Diagnostics;

namespace AAuth;

/// <summary>
/// Shared diagnostics (OpenTelemetry-compatible) for AAuth operations.
/// Uses <see cref="System.Diagnostics.ActivitySource"/> — no external OTel
/// package dependency. Consumers opt in to tracing by subscribing to the
/// <c>"AAuth"</c> activity source via their configured OTel exporter.
/// </summary>
public static class AAuthDiagnostics
{
    /// <summary>The activity source name. Use this to subscribe in OTel configuration.</summary>
    public const string SourceName = "AAuth";

    /// <summary>Shared activity source for all AAuth operations.</summary>
    public static readonly ActivitySource Source = new(SourceName, "1.0.0");

    // ── Tag keys ────────────────────────────────────────────────────────────

    /// <summary>The Signature-Key scheme used (jwt, hwk, jkt-jwt, jwks_uri).</summary>
    public const string TagScheme = "aauth.scheme";

    /// <summary>Verification level (Identity, Authorized, Pseudonymous).</summary>
    public const string TagLevel = "aauth.level";

    /// <summary>Agent identifier.</summary>
    public const string TagAgent = "aauth.agent";

    /// <summary>Granted scopes (space-separated).</summary>
    public const string TagScope = "aauth.scope";

    /// <summary>Token issuer.</summary>
    public const string TagIssuer = "aauth.issuer";

    /// <summary>Token type (aa-agent+jwt, aa-auth+jwt).</summary>
    public const string TagTokenType = "aauth.token_type";

    /// <summary>Whether issuer signature was verified.</summary>
    public const string TagIssuerVerified = "aauth.issuer_verified";
}

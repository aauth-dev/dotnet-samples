using System.Diagnostics;
using System.Diagnostics.Metrics;

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

    /// <summary>Shared metrics source for all AAuth operations.</summary>
    public static readonly Meter Meter = new(SourceName, "1.0.0");

    /// <summary>
    /// Sum of time spent waiting to avoid duplicate AAuth signature replay tuples.
    /// </summary>
    public static readonly Counter<double> SigningCreatedWait = Meter.CreateCounter<double>(
        "aauth.signing.created_wait",
        unit: "s",
        description: "Total seconds spent waiting for the next free AAuth signature created timestamp.");

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

    /// <summary>The HTTP request method.</summary>
    public const string TagHttpMethod = "http.request.method";

    /// <summary>The signed request authority.</summary>
    public const string TagAuthority = "aauth.authority";

    /// <summary>The signed request path.</summary>
    public const string TagPath = "aauth.path";

    internal static void RecordSigningCreatedWait(
        TimeSpan duration, string method, string authority, string path)
    {
        // Paths stay off the metric: they are unbounded (ids) and may identify people.
        var tags = new TagList
        {
            { TagHttpMethod, method },
            { TagAuthority, authority },
        };
        SigningCreatedWait.Add(duration.TotalSeconds, tags);
        using var activity = Source.StartActivity("AAuth.Signing.CreatedWait");
        activity?.SetTag(TagHttpMethod, method);
        activity?.SetTag(TagAuthority, authority);
        activity?.SetTag(TagPath, path);
        activity?.SetTag("aauth.signing.created_wait.duration_ms", duration.TotalMilliseconds);
        Trace.WriteLine(
            $"AAuth signing delayed {duration.TotalMilliseconds:0.###} ms for {method} {authority}{path}.",
            SourceName);
    }
}

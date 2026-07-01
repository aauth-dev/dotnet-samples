using System;
using System.Collections.Generic;
using AAuth.Crypto;
using AAuth.HttpSig;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth;

/// <summary>
/// Options for configuring an AAuth resource server via
/// <see cref="AAuthResourceServiceCollectionExtensions.AddAAuthResource"/>.
/// </summary>
public sealed class AAuthResourceOptions
{
    /// <summary>HTTPS issuer URL for this resource (used in metadata and token audience).</summary>
    public string Issuer { get; set; } = null!;

    /// <summary>
    /// Signing keys keyed by <c>kid</c>. These are served via the JWKS endpoint
    /// and used to sign resource tokens / challenges.
    /// </summary>
    public Dictionary<string, AAuthKey> SigningKeys { get; set; } = new();

    /// <summary>Maximum allowed age of inbound signatures. Default: 60 seconds.</summary>
    public TimeSpan MaxSignatureAge { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Maximum allowed skew into the future for HTTP signature timestamps.
    /// Default: 5 seconds.
    /// </summary>
    public TimeSpan MaxFutureSkew { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Clock function for deterministic testing. Default: <c>null</c> (uses UtcNow).
    /// </summary>
    public Func<DateTimeOffset>? Clock { get; set; }

    /// <summary>Enable JTI-based replay detection. Default: true.</summary>
    public bool EnableReplayDetection { get; set; } = true;

    /// <summary>
    /// Enable the resource-managed (two-party) <c>AAuth-Access</c> opaque-token
    /// flow (§Resource-Managed Authorization). When <see langword="true"/>, a
    /// default <see cref="Server.IOpaqueTokenStore"/>
    /// (<see cref="Server.InMemoryOpaqueTokenStore"/>) is registered unless the
    /// app already registered one. The resource's endpoints drive the flow via
    /// the <c>HttpContext</c> resource-managed helpers. Default: false.
    /// </summary>
    public bool EnableResourceManagedAccess { get; set; }

    /// <summary>
    /// Custom <see cref="ISignatureKeyResolver"/>. When null, <see cref="DefaultSignatureKeyResolver"/>
    /// is used with a <see cref="Discovery.JwksClient"/> registered via DI.
    /// </summary>
    public ISignatureKeyResolver? KeyResolver { get; set; }



    /// <summary>Optional human-readable resource name for metadata.</summary>
    public string? Name { get; set; }

    /// <summary>Optional Markdown description for metadata (consent display).</summary>
    public string? Description { get; set; }

    /// <summary>Optional scope descriptions for metadata.</summary>
    public Dictionary<string, string>? ScopeDescriptions { get; set; }

    /// <summary>
    /// Optional signature validity window in seconds (<c>signature_window</c>),
    /// published in resource metadata. Default <c>null</c> (the spec default of
    /// 60 s applies and the value is omitted from the document).
    /// </summary>
    public int? SignatureWindow { get; set; }

    /// <summary>
    /// Optional advisory <c>access_mode</c> published in resource metadata: one
    /// of <c>agent-token</c>, <c>aauth-access-token</c>, or <c>auth-token</c>.
    /// </summary>
    public string? AccessMode { get; set; }

    /// <summary>
    /// Optional <c>authorization_endpoint</c> URL published in resource metadata
    /// (the proactive authorization flow). When absent, the resource issues
    /// resource tokens via <c>401</c> challenges instead.
    /// </summary>
    public string? AuthorizationEndpoint { get; set; }
}

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
    /// Custom <see cref="ISignatureKeyResolver"/>. When null, <see cref="DefaultSignatureKeyResolver"/>
    /// is used with a <see cref="Discovery.JwksClient"/> registered via DI.
    /// </summary>
    public ISignatureKeyResolver? KeyResolver { get; set; }



    /// <summary>Optional human-readable resource name for metadata.</summary>
    public string? Name { get; set; }

    /// <summary>Optional scope descriptions for metadata.</summary>
    public Dictionary<string, string>? ScopeDescriptions { get; set; }
}

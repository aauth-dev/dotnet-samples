using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// Optional parameters for <see cref="TokenExchangeClient.ExchangeAsync(string, string, TokenExchangeRequest, CancellationToken)"/>.
/// Groups the deferred-consent, call-chaining, and capability/prompt options so
/// the public surface stays stable as new exchange parameters are added.
/// </summary>
public sealed class TokenExchangeRequest
{
    /// <summary>
    /// Invoked when the PS returns <c>202</c> with an interaction requirement,
    /// before polling begins. Callers display the user-facing URL/code via
    /// <see cref="AAuthInteraction.BuildUserUrl(string?)"/> and then return —
    /// polling proceeds in parallel with the user's out-of-band action. If
    /// <see langword="null"/> and the PS returns <c>202</c>, the call throws.
    /// </summary>
    public Func<AAuthInteraction, CancellationToken, Task>? OnInteractionRequired { get; init; }

    /// <summary>Optional polling cadence/timeout override for the deferred path.</summary>
    public DeferredPollerOptions? PollerOptions { get; init; }

    /// <summary>
    /// Optional upstream auth token for call-chaining scenarios. When provided,
    /// included as <c>upstream_token</c> in the POST body so the PS/AS can
    /// construct nested <c>act</c> claims preserving the delegation chain.
    /// </summary>
    public string? UpstreamToken { get; init; }

    /// <summary>
    /// Capabilities to declare to the PS in the token request body. When
    /// <see langword="null"/> (default), capabilities are inferred from the
    /// flow: <c>"interaction"</c> is sent when <see cref="OnInteractionRequired"/>
    /// is non-null. An explicit (possibly empty) list overrides inference.
    /// </summary>
    public IReadOnlyList<string>? Capabilities { get; init; }

    /// <summary>
    /// Optional OIDC <c>prompt</c> value (e.g. <c>"consent"</c>, <c>"login"</c>,
    /// <c>"none"</c>, <c>"select_account"</c>) sent to the PS to influence the
    /// consent/login experience. When <see langword="null"/> (default), no
    /// <c>prompt</c> is sent.
    /// </summary>
    public string? Prompt { get; init; }
}

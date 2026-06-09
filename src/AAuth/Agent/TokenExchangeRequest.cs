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
    /// <see cref="Interaction.BuildUserUrl(string?)"/> and then return —
    /// polling proceeds in parallel with the user's out-of-band action. If
    /// <see langword="null"/> and the PS returns <c>202</c>, the call throws.
    /// </summary>
    public Func<Interaction, CancellationToken, Task>? OnInteractionRequired { get; init; }

    /// <summary>Optional polling cadence/timeout override for the deferred path.</summary>
    public DeferredPollerOptions? PollerOptions { get; init; }

    /// <summary>
    /// Optional upstream auth token for call-chaining scenarios. When provided,
    /// included as <c>upstream_token</c> in the POST body so the PS/AS can
    /// construct nested <c>act</c> claims preserving the delegation chain.
    /// </summary>
    public string? UpstreamToken { get; init; }

    /// <summary>
    /// Optional sub-agent agent token (<c>subagent_token</c>) for parent-mediated
    /// authorization (§Sub-Agents). When set, the signing agent is the parent and
    /// the PS/AS issues an auth token bound to the sub-agent's key, recording the
    /// parent in the <c>act</c> chain. The parent MUST be named by the
    /// <c>subagent_token</c>'s <c>parent_agent</c> claim.
    /// </summary>
    public string? SubagentToken { get; init; }

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

    /// <summary>
    /// Optional Markdown <c>justification</c> declaring why access is requested;
    /// the PS SHOULD present it to the user during consent (§Agent Token Request).
    /// </summary>
    public string? Justification { get; init; }

    /// <summary>
    /// Optional OIDC <c>login_hint</c> about who to authorize
    /// ([@!OpenID.Core] §3.1.2.1, §Agent Token Request).
    /// </summary>
    public string? LoginHint { get; init; }

    /// <summary>
    /// Optional <c>tenant</c> identifier (OpenID Connect Enterprise Extensions,
    /// §Agent Token Request).
    /// </summary>
    public string? Tenant { get; init; }

    /// <summary>
    /// Optional <c>domain_hint</c> (OpenID Connect Enterprise Extensions,
    /// §Agent Token Request).
    /// </summary>
    public string? DomainHint { get; init; }

    /// <summary>
    /// Optional <c>platform</c> identifier for the agent's runtime platform.
    /// MUST be a value from the AAuth Platform Value Registry; used for display
    /// at the PS consent screen / connected-agents dashboard (§Agent Token Request).
    /// </summary>
    public string? Platform { get; init; }

    /// <summary>
    /// Optional <c>device</c> string identifying the device/browser for display
    /// (e.g. <c>"Chrome on macOS"</c>). MUST be printable UTF-8, ≤ 64 characters,
    /// no control characters or PII (§Agent Token Request).
    /// </summary>
    public string? Device
    {
        get => _device;
        init => _device = ValidateDevice(value);
    }

    private readonly string? _device;

    // §Agent Token Request: `device` MUST be printable (no control characters) and
    // ≤ 64 characters. Reject anything outside printable ASCII (32–126) so display
    // surfaces never receive control characters; allow null/empty (the field is optional).
    private static string? ValidateDevice(string? value)
    {
        if (value is null)
        {
            return null;
        }

        if (value.Length > 64)
        {
            throw new ArgumentException(
                $"device must be at most 64 characters (was {value.Length}).", nameof(Device));
        }

        foreach (var ch in value)
        {
            if (ch < ' ' || ch > '~')
            {
                throw new ArgumentException(
                    "device must contain only printable ASCII characters (no control characters).",
                    nameof(Device));
            }
        }

        return value;
    }

    /// <summary>
    /// Invoked when the PS returns <c>202</c> with
    /// <c>requirement=clarification</c> during consent. The callback receives
    /// the parsed question and returns the agent's chosen
    /// <see cref="ClarificationResponse"/> (respond / update / cancel), which
    /// the exchange applies before resuming polling (§Clarification Chat). If
    /// <see langword="null"/> and the PS asks for clarification, the call throws.
    /// </summary>
    public Func<Headers.ClarificationRequirement, CancellationToken, Task<ClarificationResponse>>? OnClarificationRequired { get; init; }

    /// <summary>
    /// Maximum number of clarification rounds the agent will engage in before
    /// giving up (§Clarification Limits, default 5).
    /// </summary>
    public int MaxClarificationRounds { get; init; } = ClarificationExchange.DefaultMaxRounds;
}

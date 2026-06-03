using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.Tokens;

namespace AAuth.Access;

/// <summary>
/// Parameters for <see cref="AccessServerClient.FederateAsync"/>. Groups the
/// signed request payload, the delivery-verification context, and the
/// deferred-consent options so the public surface stays stable as new
/// federation parameters are added.
/// </summary>
public sealed class AccessServerRequest
{
    /// <summary>
    /// The resource token (<c>aa-resource+jwt</c>) whose <c>aud</c> is the
    /// Access Server. Submitted as <c>resource_token</c> in the POST body.
    /// </summary>
    public required string ResourceToken { get; init; }

    /// <summary>
    /// The agent's agent token (<c>aa-agent+jwt</c>). Submitted as
    /// <c>agent_token</c> in the POST body so the AS can identify and bind the
    /// agent.
    /// </summary>
    public required string AgentToken { get; init; }

    /// <summary>
    /// Optional upstream auth token for call-chaining scenarios. When provided,
    /// included as <c>upstream_token</c> in the POST body so the AS can
    /// construct nested <c>act</c> claims preserving the delegation chain.
    /// </summary>
    public string? UpstreamToken { get; init; }

    /// <summary>
    /// The expected audience of the AS-issued auth token — the resource URL
    /// (the resource token's <c>iss</c>). Used by Auth Token Delivery step 3.
    /// </summary>
    public required string ExpectedAudience { get; init; }

    /// <summary>
    /// The agent identifier that submitted the request. Used by Auth Token
    /// Delivery step 4 (<c>agent</c> / <c>act.sub</c> checks).
    /// </summary>
    public required string ExpectedAgentId { get; init; }

    /// <summary>
    /// The agent's signing key, for the <c>cnf.jwk</c> binding check
    /// (Auth Token Delivery step 5).
    /// </summary>
    public required IAAuthKey AgentKey { get; init; }

    /// <summary>
    /// Optional act context for chain consistency (Auth Token Delivery step 6).
    /// For direct authorization leave <see langword="null"/>; for call chaining
    /// pass the upstream act that was submitted with the request.
    /// </summary>
    public JsonObject? ExpectedActContext { get; init; }

    /// <summary>
    /// Optional requested scope from the resource token (Auth Token Delivery
    /// step 7). When provided, verifies the auth token's scope is not broader.
    /// </summary>
    public string? RequestedScope { get; init; }

    /// <summary>
    /// Invoked when the AS returns <c>202</c> with an interaction requirement,
    /// before polling begins. If <see langword="null"/> and the AS returns
    /// <c>202 requirement=interaction</c>, the call throws.
    /// </summary>
    public Func<Interaction, CancellationToken, Task>? OnInteractionRequired { get; init; }

    /// <summary>
    /// Invoked when the AS returns <c>202 requirement=claims</c> (§Claims
    /// Required) to request identity claims it needs for a policy decision.
    /// The callback receives the requested claim names and MUST return an
    /// <see cref="ClaimsResponse"/> carrying a directed user identifier
    /// (<see cref="ClaimsResponse.Subject"/>) plus the released claims;
    /// <see cref="AccessServerClient.FederateAsync"/> POSTs them (signed) to
    /// the AS's pending <c>Location</c> URL and then resumes polling. If
    /// <see langword="null"/> and the AS returns <c>202 requirement=claims</c>,
    /// the call throws <see cref="NotSupportedException"/>.
    /// </summary>
    public Func<ClaimsRequirement, CancellationToken, Task<ClaimsResponse>>? OnClaimsRequired { get; init; }

    /// <summary>Optional polling cadence/timeout override for the deferred path.</summary>
    public DeferredPollerOptions? PollerOptions { get; init; }
}

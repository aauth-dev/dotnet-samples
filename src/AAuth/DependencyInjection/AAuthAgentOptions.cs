using System;
using System.Net.Http;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;

namespace AAuth;

/// <summary>
/// Options for an AAuth agent registered with <c>AddAAuthAgent(name)</c>; the
/// <c>IConfiguration</c> overload binds them from a section such as <c>AAuth:Agents:&lt;name&gt;</c>.
/// Every scalar binds from configuration; members typed as delegates or instances are
/// code-only (binding ignores them).
/// </summary>
/// <remarks>
/// Configure exactly one identity source: an agent token (<see cref="AgentToken"/>,
/// <see cref="AgentTokenFactory"/> and/or <see cref="TokenRefresher"/>), <see cref="SelfIssued"/>,
/// <see cref="AgentProvider"/>, <see cref="JwksUri"/>, or a generic <see cref="SignatureKeyProvider"/>.
/// </remarks>
public class AAuthAgentOptions
{
    /// <summary>The handle of the agent's signing key in the registered <see cref="IKeyStore"/>.</summary>
    public string? KeyHandle { get; set; }

    /// <summary>Code-only: the agent's signing key, instead of <see cref="KeyHandle"/>.</summary>
    public IAAuthSigner? Signer { get; set; }

    /// <summary>Code-only: the egress policy. Default <see cref="AAuthEgressPolicy.Production"/>.</summary>
    public AAuthEgressPolicy? EgressPolicy { get; set; }

    /// <summary>Loopback origins a development agent may call (<see cref="AAuthEgressPolicy.ForDevelopmentLoopback"/>).</summary>
    public string[]? DevelopmentLoopbackOrigins { get; set; }

    /// <summary>Code-only: the transport under the signer, with its <see cref="TransportContract"/>.</summary>
    public HttpMessageHandler? InnerHandler { get; set; }

    /// <summary>Code-only: what <see cref="InnerHandler"/> guarantees about egress.</summary>
    public AAuthTransportContract? TransportContract { get; set; }

    /// <summary>An already-held agent JWT. Combine with <see cref="TokenRefresher"/> for renewal.</summary>
    public string? AgentToken { get; set; }

    /// <summary>Code-only: returns the current agent JWT for each request.</summary>
    public Func<string>? AgentTokenFactory { get; set; }

    /// <summary>Code-only: obtains a fresh agent token before expiry. Caller-owned.</summary>
    public ITokenRefresher? TokenRefresher { get; set; }

    /// <summary>Refresh when less than this remains before <c>exp</c>. Default five minutes.</summary>
    public TimeSpan? TokenRefreshThreshold { get; set; }

    /// <summary>A self-issued agent identity, signed with the agent's own key.</summary>
    public AAuthSelfIssuedAgentOptions SelfIssued { get; set; } = new();

    /// <summary>An agent enrolled at an agent provider, refreshed with the key at <see cref="KeyHandle"/>.</summary>
    public AAuthAgentProviderOptions AgentProvider { get; set; } = new();

    /// <summary>A server identity published through metadata (<c>jwks_uri</c> scheme).</summary>
    public AAuthJwksUriIdentityOptions JwksUri { get; set; } = new();

    /// <summary>Code-only: a generic Signature Keys provider. Excludes AAuth authorization flows.</summary>
    public ISignatureKeyProvider? SignatureKeyProvider { get; set; }

    /// <summary>The Person Server. Defaults to the agent token's <c>ps</c> claim.</summary>
    public string? PersonServer { get; set; }

    /// <summary>Handle <c>401</c> challenges by token exchange. Default: on when <see cref="PersonServer"/> or call chaining is set.</summary>
    public bool? HandleChallenges { get; set; }

    /// <summary>Challenge-handling tuning: clarification, prompt, PS capabilities and polling.</summary>
    public ChallengeHandlingOptions Challenge { get; set; } = new();

    /// <summary>Handle resource <c>202</c> interaction and approval. Default: on when an <see cref="Interaction"/> callback is set.</summary>
    public bool? HandleInteractions { get; set; }

    /// <summary>Resource interaction handling: callbacks and polling.</summary>
    public InteractionHandlingOptions Interaction { get; set; } = new();

    /// <summary><c>AAuth-Capabilities</c> declared on every signed request.</summary>
    public string[]? Capabilities { get; set; }

    /// <summary>Code-only: the agent's own approved mission; person tokens carry its <c>mission_s256</c>.</summary>
    public Mission? Mission { get; set; }

    /// <summary>Code-only: returns the upstream auth token to chain (#call-chaining).</summary>
    public Func<string?>? UpstreamTokenProvider { get; set; }

    /// <summary>Chain the verified upstream auth token of the current request (<c>IHttpContextAccessor</c>).</summary>
    public bool ChainFromHttpContext { get; set; }

    /// <summary>Capture <c>AAuth-Access</c> tokens and replay them (resource-managed access).</summary>
    public bool EnableResourceManagedAccess { get; set; }

    /// <summary>Code-only: per-origin store for resource-managed access. Default in-memory.</summary>
    public IAAuthAccessStore? AAuthAccessStore { get; set; }

    /// <summary>Code-only: observes each RFC 9421 signature base.</summary>
    public Action<HttpRequestMessage, string>? OnSignatureBase { get; set; }

    /// <summary>
    /// Code-only: the cache of person and auth tokens obtained by challenge handling. Defaults to the
    /// <see cref="IAAuthTokenCache"/> keyed by the agent name, then an unkeyed one, then in-memory.
    /// </summary>
    public IAAuthTokenCache? TokenCache { get; set; }
}

/// <summary>A self-issued agent identity (<c>AAuthClientBuilder.SelfIssuing</c>).</summary>
public sealed class AAuthSelfIssuedAgentOptions
{
    /// <summary>The agent token issuer: the agent's own server identifier.</summary>
    public string? Issuer { get; set; }

    /// <summary>The agent identifier (<c>sub</c>).</summary>
    public string? Subject { get; set; }

    /// <summary>The key ID in the issuer's JWKS. Default: the key's JWK thumbprint.</summary>
    public string? KeyId { get; set; }
}

/// <summary>An agent-provider enrolment (<c>AAuthClientBuilder.Enrolled</c>).</summary>
public sealed class AAuthAgentProviderOptions
{
    /// <summary>The agent provider's refresh endpoint.</summary>
    public string? RefreshEndpoint { get; set; }
}

/// <summary>A server identity using the <c>jwks_uri</c> scheme (<c>AAuthClientBuilder.UseJwksUri</c>).</summary>
public sealed class AAuthJwksUriIdentityOptions
{
    /// <summary>The signer identifier.</summary>
    public string? Id { get; set; }

    /// <summary>The well-known metadata document name.</summary>
    public string? Dwk { get; set; }

    /// <summary>The key ID in the JWKS.</summary>
    public string? KeyId { get; set; }
}

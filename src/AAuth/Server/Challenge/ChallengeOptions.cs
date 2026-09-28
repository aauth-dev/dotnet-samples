using System.Collections.Generic;
using AAuth.Crypto;
using AAuth.Server.Verification;

namespace AAuth.Server.Challenge;

/// <summary>
/// Configuration for <see cref="AAuthChallengeMiddleware"/> which automatically
/// issues 401 challenges with resource tokens when the resource requires an auth
/// token but only an agent token is presented.
/// </summary>
public sealed class ChallengeOptions
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; set; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    /// <summary>
    /// Access mode controlling whether the middleware challenges or passes through.
    /// Default: <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public AAuthAccessMode AccessMode { get; init; } = AAuthAccessMode.RequireAuthToken;

    /// <summary>
    /// The resource's signing key used to sign resource tokens.
    /// Required when <see cref="AccessMode"/> is <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public IAAuthKey? ResourceSigningKey { get; init; }

    /// <summary>
    /// Key identifier for the resource signing key (<c>kid</c> in the resource token header).
    /// Required when <see cref="AccessMode"/> is <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public string? ResourceKeyId { get; init; }

    /// <summary>
    /// The resource's own identifier (used as <c>iss</c> in the resource token).
    /// Required when <see cref="AccessMode"/> is <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public string? ResourceIdentifier { get; init; }
    public System.Func<Microsoft.AspNetCore.Http.HttpContext, string?>? RequestedAccount { get; init; }

    /// <summary>
    /// The resource's own Access Server (four-party): the resource-token <c>aud</c>.
    /// When null the audience is the PS that issued the presented person token (three-party).
    /// </summary>
    public string? AccessServer { get; init; }

    /// <summary>
    /// Default scopes to request in the resource token. Space-separated.
    /// </summary>
    public string? DefaultScopes { get; init; }
    public IReadOnlyDictionary<string, string>? ScopeDescriptions { get; init; }

    /// <summary>
    /// Optional filter on allowed Signature-Key schemes. When set, requests using
    /// schemes not in this set are rejected with 401 before challenge logic runs.
    /// When null, all schemes are accepted.
    /// </summary>
    public IReadOnlySet<string>? AllowedSignatureKeySchemes { get; init; }
}

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
    /// <summary>
    /// Access mode controlling whether the middleware challenges or passes through.
    /// Default: <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public AAuthAccessMode AccessMode { get; init; } = AAuthAccessMode.RequireAuthToken;

    /// <summary>
    /// The resource's signing key used to sign resource tokens.
    /// Required when <see cref="AccessMode"/> is <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public AAuthKey? ResourceSigningKey { get; init; }

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

    /// <summary>
    /// Explicit audience for resource tokens. When set, this value is used as
    /// <c>aud</c> in the resource token (e.g. the resource's own AS URL in a four-party flow).
    /// When null, the audience is resolved from the agent token's <c>ps</c> claim (three-party).
    /// </summary>
    public string? PersonServerAudience { get; init; }

    /// <summary>
    /// Default scopes to request in the resource token. Space-separated.
    /// </summary>
    public string? DefaultScopes { get; init; }

    /// <summary>
    /// Optional filter on allowed Signature-Key schemes. When set, requests using
    /// schemes not in this set are rejected with 401 before challenge logic runs.
    /// When null, all schemes are accepted.
    /// </summary>
    public IReadOnlySet<string>? AllowedSignatureKeySchemes { get; init; }

    /// <summary>
    /// When <see langword="true"/>, the resource is mission-aware (§Terminology:
    /// "a mission-aware resource includes the mission object from the
    /// <c>AAuth-Mission</c> header in the resource tokens it issues"). If the
    /// challenged request carries a valid <c>AAuth-Mission</c> header, the issued
    /// resource token includes the mission object (<c>approver</c> + <c>s256</c>)
    /// so the mission context flows to the PS. When <see langword="false"/>
    /// (default) the header is ignored.
    /// </summary>
    public bool MissionAware { get; init; }
}

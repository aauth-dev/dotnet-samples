using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

public static class AuthTokenResponse
{
    public static Task<IResult> CreateTrackedAsync(Func<CancellationToken, ValueTask<string>> mint, DateTimeOffset ceiling,
        IJtiStore inventory, IReadOnlyCollection<TokenRegistration> sources, TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
        => CreateTrackedAsync(mint, ceiling, inventory, sources, "auth_token", timeProvider, cancellationToken);

    /// <summary>
    /// Mint and register a token derived from <paramref name="sources"/>, and
    /// return <c>{ <paramref name="member"/>, expires_in }</c>. Use
    /// <c>"person_token"</c> for the person token endpoint.
    /// </summary>
    public static async Task<IResult> CreateTrackedAsync(Func<CancellationToken, ValueTask<string>> mint, DateTimeOffset ceiling,
        IJtiStore inventory, IReadOnlyCollection<TokenRegistration> sources, string member, TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default, IResult? ceilingExpired = null)
    {
        ArgumentNullException.ThrowIfNull(sources);
        var clock = timeProvider ?? TimeProvider.System;
        IResult Expired() => AAuthProblemDetails.SourceExpired(sources, clock.GetUtcNow(), ceilingExpired);
        var (token, failure) = await MintTrackedAsync(mint, ceiling, inventory, sources, clock,
            Expired, cancellationToken);
        return failure ?? Create(token!, ceiling, clock, member, Expired);
    }

    // Mint a token and record it as a grant of its sources; a failure is expired or revoked.
    internal static async Task<(string? Token, IResult? Failure)> MintTrackedAsync(Func<CancellationToken, ValueTask<string>> mint, DateTimeOffset ceiling,
        IJtiStore inventory, IReadOnlyCollection<TokenRegistration> sources, TimeProvider clock,
        Func<IResult> expired, CancellationToken cancellationToken)
    {
        if (ceiling.ToUnixTimeSeconds() <= clock.GetUtcNow().ToUnixTimeSeconds()) return (null, expired());
        if (await AAuthSourceGuard.CheckAsync(inventory, sources, clock, cancellationToken).ConfigureAwait(false) is { } failure)
            return (null, failure.ToFreshResult(sources, clock.GetUtcNow(), expired()));
        string token;
        try { token = await mint(cancellationToken); }
        catch (AuthTokenExpiredException) { return (null, expired()); }
        var payload = TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");
        var registration = TokenRegistration.FromPayload(payload);
        var grant = new TokenGrant(registration.Token,
            (string?)payload["aud"] ?? throw new TokenVerificationException("Issued token missing aud."), registration.ExpiresAt);
        var keys = sources.Where(source => source.Credential != TokenCredential.Resource)
            .Select(source => source.Token).ToArray();
        if (registration.ExpiresAt > ceiling || !await inventory.RegisterGrantAsync(keys, grant, cancellationToken))
        {
            if (await AAuthSourceGuard.CheckAsync(inventory, sources, clock, cancellationToken).ConfigureAwait(false) is { } race)
                return (null, race.ToFreshResult(sources, clock.GetUtcNow(), Revoked()));
            return (null, Revoked());
        }
        return (token, null);
    }

    public static async Task<IResult> CreateAsync(Func<CancellationToken, ValueTask<string>> mint, DateTimeOffset ceiling,
        TimeProvider? timeProvider = null, CancellationToken cancellationToken = default)
    {
        var clock = timeProvider ?? TimeProvider.System;
        if (ceiling.ToUnixTimeSeconds() <= clock.GetUtcNow().ToUnixTimeSeconds())
            return Expired();
        try { return Create(await mint(cancellationToken), ceiling, clock); }
        catch (AuthTokenExpiredException) { return Expired(); }
    }

    public static IResult Create(string token, DateTimeOffset ceiling, TimeProvider? timeProvider = null)
        => Create(token, ceiling, timeProvider, "auth_token", Expired);

    private static IResult Create(string token, DateTimeOffset ceiling, TimeProvider? timeProvider, string member, Func<IResult> expired)
    {
        var payload = TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");
        var expiration = payload["exp"]!.GetValue<long>();
        var remaining = expiration - (timeProvider ?? TimeProvider.System).GetUtcNow().ToUnixTimeSeconds();
        if (remaining <= 0 || expiration > ceiling.ToUnixTimeSeconds())
            return expired();
        return Results.Json(new JsonObject { [member] = token, ["expires_in"] = remaining },
            statusCode: StatusCodes.Status200OK);
    }

    /// <summary>The token the request depends on expired before issuance (polling <c>expired</c>).</summary>
    public static IResult Expired() => AAuthProblemDetails.Create(
        "expired", "The verified authorization context has expired.", statusCode: StatusCodes.Status408RequestTimeout);

    /// <summary>A token the request depends on was revoked (polling <c>revoked</c>).</summary>
    public static IResult Revoked() => AAuthProblemDetails.Create(
        "revoked", "A token the request depends on is revoked or unknown.", statusCode: StatusCodes.Status403Forbidden);
}

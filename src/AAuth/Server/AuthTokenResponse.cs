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
    public static async Task<IResult> CreateTrackedAsync(Func<string> mint, DateTimeOffset ceiling,
        IJtiStore inventory, IReadOnlyCollection<TokenKey> sources, TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
        => await CreateTrackedAsync(mint, ceiling, inventory, sources, "auth_token", timeProvider, cancellationToken);

    /// <summary>
    /// Mint and register a token derived from <paramref name="sources"/>, and
    /// return <c>{ <paramref name="member"/>, expires_in }</c>. Use
    /// <c>"person_token"</c> for the person token endpoint.
    /// </summary>
    public static async Task<IResult> CreateTrackedAsync(Func<string> mint, DateTimeOffset ceiling,
        IJtiStore inventory, IReadOnlyCollection<TokenKey> sources, string member, TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        var clock = timeProvider ?? TimeProvider.System;
        if (ceiling.ToUnixTimeSeconds() <= clock.GetUtcNow().ToUnixTimeSeconds()) return Expired();
        foreach (var source in sources)
            if (await inventory.IsRevokedAsync(source, cancellationToken))
                return Revoked();
        string token;
        try { token = mint(); }
        catch (AuthTokenExpiredException) { return Expired(); }
        var payload = TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");
        var registration = TokenRegistration.FromPayload(payload);
        var grant = new TokenGrant(registration.Token,
            (string?)payload["aud"] ?? throw new TokenVerificationException("Issued token missing aud."), registration.ExpiresAt);
        if (registration.ExpiresAt > ceiling || !await inventory.RegisterGrantAsync(sources, grant, cancellationToken))
            return Revoked();
        return Create(token, ceiling, clock, member);
    }

    public static IResult Create(Func<string> mint, DateTimeOffset ceiling, TimeProvider? timeProvider = null)
    {
        var clock = timeProvider ?? TimeProvider.System;
        if (ceiling.ToUnixTimeSeconds() <= clock.GetUtcNow().ToUnixTimeSeconds())
            return Expired();
        try { return Create(mint(), ceiling, clock); }
        catch (AuthTokenExpiredException) { return Expired(); }
    }

    public static IResult Create(string token, DateTimeOffset ceiling, TimeProvider? timeProvider = null)
        => Create(token, ceiling, timeProvider, "auth_token");

    private static IResult Create(string token, DateTimeOffset ceiling, TimeProvider? timeProvider, string member)
    {
        var payload = TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");
        var expiration = payload["exp"]!.GetValue<long>();
        var remaining = expiration - (timeProvider ?? TimeProvider.System).GetUtcNow().ToUnixTimeSeconds();
        if (remaining <= 0 || expiration > ceiling.ToUnixTimeSeconds())
            return Expired();
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

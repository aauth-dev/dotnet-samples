using System;
using System.Collections.Generic;
using System.Linq;
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
    {
        var clock = timeProvider ?? TimeProvider.System;
        if (ceiling.ToUnixTimeSeconds() <= clock.GetUtcNow().ToUnixTimeSeconds()) return Expired();
        foreach (var source in sources)
            if (await inventory.IsRevokedAsync(source, cancellationToken))
                return AAuthProblemDetails.Create("invalid_agent_token", "The source authorization is revoked.", statusCode: 400);
        string token;
        try { token = mint(); }
        catch (AuthTokenExpiredException) { return Expired(); }
        var payload = TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");
        var registration = TokenRegistration.FromPayload(payload);
        var grant = new TokenGrant(registration.Token,
            (string?)payload["aud"] ?? throw new TokenVerificationException("Auth token missing aud."), registration.ExpiresAt);
        if (registration.ExpiresAt > ceiling || !await inventory.RegisterGrantAsync(sources, grant, cancellationToken))
            return AAuthProblemDetails.Create("invalid_agent_token", "The source authorization is revoked, expired, or unknown.", statusCode: 400);
        return Create(token, ceiling, clock);
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
    {
        var payload = TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");
        var expiration = payload["exp"]!.GetValue<long>();
        var remaining = expiration - (timeProvider ?? TimeProvider.System).GetUtcNow().ToUnixTimeSeconds();
        if (remaining <= 0 || expiration > ceiling.ToUnixTimeSeconds())
            return Expired();
        return Results.Ok(new { auth_token = token, expires_in = remaining });
    }

    public static IResult Expired() => AAuthProblemDetails.Create(
        "invalid_agent_token", "The verified authorization context has expired.", statusCode: StatusCodes.Status400BadRequest);
}
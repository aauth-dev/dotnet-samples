using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json.Nodes;
using AAuth.Tokens;

namespace AAuth.Server;

public sealed record TokenRegistration(TokenKey Token, DateTimeOffset ExpiresAt)
{
    public static TokenRegistration FromVerified(TokenVerifier.VerifiedToken token)
        => FromPayload(token.Payload);

    public static async Task<IReadOnlyList<TokenKey>> RegisterAsync(IJtiStore inventory,
        IReadOnlyCollection<TokenRegistration> tokens, CancellationToken cancellationToken = default)
    {
        var keys = new List<TokenKey>();
        foreach (var token in tokens)
        {
            if (!await inventory.RegisterAsync(token.Token, token.ExpiresAt, cancellationToken))
                throw new TokenVerificationException("Source token is revoked, expired, or has conflicting inventory.");
            keys.Add(token.Token);
        }
        return keys;
    }

    internal static TokenRegistration FromPayload(JsonObject payload)
        => new(new TokenKey((string?)payload["iss"] ?? throw new TokenVerificationException("Token missing iss."),
            (string?)payload["jti"] ?? throw new TokenVerificationException("Token missing jti.")),
            DateTimeOffset.FromUnixTimeSeconds((long)payload["exp"]!));
}
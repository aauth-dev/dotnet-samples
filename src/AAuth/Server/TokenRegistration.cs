using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json.Nodes;
using AAuth.Tokens;

namespace AAuth.Server;

public sealed record TokenRegistration(TokenKey Token, DateTimeOffset ExpiresAt)
{
    /// <summary>The request parameter that carried the token; <see langword="null"/> for the <c>Signature-Key</c> token.</summary>
    public TokenCredential? Credential { get; init; }

    /// <summary>The JWT <c>typ</c> of the source token when it was verified.</summary>
    public string? TokenType { get; init; }

    public static TokenRegistration FromVerified(TokenVerifier.VerifiedToken token, TokenCredential? credential = null)
        => FromPayload(token.Payload) with { Credential = credential, TokenType = token.TokenType };

    public static async Task<IReadOnlyList<TokenKey>> RegisterAsync(IJtiStore inventory,
        IReadOnlyCollection<TokenRegistration> tokens, CancellationToken cancellationToken = default)
    {
        var keys = new List<TokenKey>();
        foreach (var token in tokens)
        {
            if (!await inventory.RegisterAsync(token.Token, token.ExpiresAt, cancellationToken))
                throw new TokenVerificationException(Errors.SignatureErrorCode.RevokedJwt,
                    "Source token is revoked, expired, or has conflicting inventory.") { Credential = token.Credential };
            keys.Add(token.Token);
        }
        return keys;
    }

    internal static TokenRegistration FromPayload(JsonObject payload)
        => new(new TokenKey((string?)payload["iss"] ?? throw new TokenVerificationException("Token missing iss."),
            (string?)payload["jti"] ?? throw new TokenVerificationException("Token missing jti.")),
            DateTimeOffset.FromUnixTimeSeconds((long)payload["exp"]!));
}
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;

namespace AAuth.Events;

public sealed class SubscribeTokenBuilder
{
    public required string Issuer { get; init; }
    public required string Subject { get; init; }
    public required string Audience { get; init; }
    public required string Eid { get; init; }
    public required IAAuthSigner Key { get; init; }
    public required IAAuthKey ConfirmationKey { get; init; }
    public required string KeyId { get; init; }
    public long? MaxUses { get; init; }
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);
    public TokenVerifier Verifier { get; init; } = new();

    public ValueTask<string> BuildAsync(CancellationToken cancellationToken = default)
    {
        var now = Verifier.TimeProvider.GetUtcNow();
        var payload = new JsonObject
        {
            ["iss"] = Issuer, ["dwk"] = EventsTokens.AgentDwk, ["sub"] = Subject,
            ["aud"] = Audience, ["eid"] = Eid,
            ["cnf"] = new JsonObject { ["jwk"] = ConfirmationKey.ToPublicJwk() },
            ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = now.Add(Lifetime).ToUnixTimeSeconds()
        };
        if (MaxUses is not null) payload["max_uses"] = MaxUses.Value;
        return EventsTokens.CreateAsync(Key, KeyId, payload, true, Verifier, cancellationToken);
    }
}

public sealed class EventTokenBuilder
{
    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public required string Eid { get; init; }
    public required IAAuthSigner Key { get; init; }
    public required string KeyId { get; init; }

    /// <summary>The event's identity: <c>(iss, jti)</c> is the AP and agent deduplication key.</summary>
    public string Jti { get; init; } = Guid.NewGuid().ToString("N");
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);
    public TokenVerifier Verifier { get; init; } = new();

    public ValueTask<string> BuildAsync(CancellationToken cancellationToken = default)
    {
        var now = Verifier.TimeProvider.GetUtcNow();
        return EventsTokens.CreateAsync(Key, KeyId, new JsonObject
        {
            ["iss"] = Issuer, ["dwk"] = EventsTokens.ResourceDwk, ["aud"] = Audience, ["eid"] = Eid, ["jti"] = Jti,
            ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = now.Add(Lifetime).ToUnixTimeSeconds()
        }, false, Verifier, cancellationToken);
    }
}
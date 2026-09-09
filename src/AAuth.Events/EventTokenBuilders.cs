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
    public required IAAuthKey Key { get; init; }
    public required IAAuthKey ConfirmationKey { get; init; }
    public required string KeyId { get; init; }
    public long? MaxUses { get; init; }
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);
    public TokenVerifier Verifier { get; init; } = new();

    public string Build()
    {
        var now = Verifier.Clock();
        var payload = new JsonObject
        {
            ["iss"] = Issuer, ["dwk"] = EventsTokens.AgentDwk, ["sub"] = Subject,
            ["aud"] = Audience, ["eid"] = Eid,
            ["cnf"] = new JsonObject { ["jwk"] = ConfirmationKey.ToPublicJwk() },
            ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = now.Add(Lifetime).ToUnixTimeSeconds()
        };
        if (MaxUses is not null) payload["max_uses"] = MaxUses.Value;
        return EventsTokens.Create(Key, KeyId, payload, true, Verifier);
    }
}

public sealed class EventTokenBuilder
{
    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public required string Eid { get; init; }
    public required IAAuthKey Key { get; init; }
    public required string KeyId { get; init; }
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);
    public TokenVerifier Verifier { get; init; } = new();

    public string Build()
    {
        var now = Verifier.Clock();
        return EventsTokens.Create(Key, KeyId, new JsonObject
        {
            ["iss"] = Issuer, ["dwk"] = EventsTokens.ResourceDwk, ["aud"] = Audience, ["eid"] = Eid,
            ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = now.Add(Lifetime).ToUnixTimeSeconds()
        }, false, Verifier);
    }
}
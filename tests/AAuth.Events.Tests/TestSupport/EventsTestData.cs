using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tests.TestSupport;

internal static class EventsTestData
{
    public static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(1_750_000_000);

    public static string SegmentJson(string compactToken, int index) =>
        (JsonNode.Parse(Base64UrlEncoder.DecodeBytes(compactToken.Split('.')[index])) as JsonObject)!
            .ToJsonString();

    public static SubscribeTokenArtifact Subscribe(
        IAAuthKey signingKey,
        IAAuthKey? confirmationKey = null,
        string? eid = null,
        long? maxUses = null) =>
        new SubscribeTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:agent@ap.example",
            Audience = "https://resource.example",
            KeyId = "ap-1",
            Key = signingKey,
            ConfirmationKey = confirmationKey ?? AAuthKey.Generate(),
            IssuedAt = Now,
            Lifetime = TimeSpan.FromMinutes(5),
            EventId = eid,
            MaxUses = maxUses,
        }.Build();

    public static EventTokenArtifact Event(
        IAAuthKey signingKey,
        string? jti = null,
        string eid = "event-1") =>
        new EventTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "aauth:agent@ap.example",
            Eid = eid,
            KeyId = "resource-1",
            Key = signingKey,
            IssuedAt = Now,
            Lifetime = TimeSpan.FromMinutes(5),
            Jti = jti,
        }.Build();
}

using AAuth.Crypto;
using AAuth.Tokens;

namespace AAuth.Testing;

public static class TestTokens
{
    public static readonly string Resource = BuildResource();
    public static readonly string UpdatedResource = BuildResource();

    private static string BuildResource() => new ResourceTokenBuilder
    {
        Issuer = "https://resource.test", Audience = "https://ps.test",
        Agent = "aauth:demo@ap.test", AgentJkt = "fixture-key",
        Key = AAuthKey.Generate(), KeyId = "resource-1",
    }.Build();
}
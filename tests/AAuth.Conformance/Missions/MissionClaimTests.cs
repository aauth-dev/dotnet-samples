using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the optional <c>mission_s256</c> claim carried in resource,
/// person and auth tokens (§Resource Token Structure, §Person Token Structure,
/// §Auth Token Structure): the unpadded base64url SHA-256 of the mission blob.
/// </summary>
public class MissionClaimTests
{
    private const string Iss = "https://resource.example";
    private const string Aud = "https://ps.example";
    private const string S256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    private static JsonObject PayloadOf(string jwt)
    {
        var parts = jwt.Split('.');
        return (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!;
    }

    private static ValueTask<string> ResourceTokenAsync(string? missionS256) => new ResourceTokenBuilder
    {
        ScopeDescriptions = TestScopeDefinitions.Resource,
        EgressPolicy = TestEgress.Policy,
        Issuer = Iss,
        Audience = Aud,
        PersonServer = Aud,
        Subject = "person-1",
        PresentedJti = "person-token-1",
        AgentJkt = "thumb",
        Key = AAuthKey.Generate(),
        KeyId = "r1",
        Scope = "whoami",
        MissionS256 = missionS256,
    }.BuildAsync();

    private static ValueTask<string> AuthTokenAsync(IAAuthSigner issuerKey, IAAuthKey agentKey, string? missionS256) => new AuthTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
        Issuer = Aud,
        Audience = Iss,
        PersonServer = Aud,
        Subject = "person-1",
        AgentConfirmationKey = agentKey,
        Key = issuerKey,
        KeyId = "p1",
        Scope = "whoami",
        MissionS256 = missionS256,
    }.BuildAsync();

    [Fact(DisplayName = "§Resource Token Structure — mission_s256 omitted when not set")]
    public async Task ResourceToken_OmitsMission_WhenNotSet()
    {
        var payload = PayloadOf(await ResourceTokenAsync(null));
        Assert.False(payload.ContainsKey("mission_s256"));
        Assert.False(payload.ContainsKey("mission"));
    }

    [Fact(DisplayName = "§Resource Token Structure — mission_s256 emitted as a string when set")]
    public async Task ResourceToken_EmitsMission_WhenSet()
    {
        var payload = PayloadOf(await ResourceTokenAsync(S256));
        Assert.Equal(S256, (string?)payload["mission_s256"]);
        Assert.False(payload.ContainsKey("mission"));
    }

    [Fact(DisplayName = "§Auth Token Structure — mission_s256 omitted when not set")]
    public async Task AuthToken_OmitsMission_WhenNotSet()
    {
        Assert.False(PayloadOf(await AuthTokenAsync(AAuthKey.Generate(), AAuthKey.Generate(), null)).ContainsKey("mission_s256"));
    }

    [Fact(DisplayName = "§Auth Token Structure — mission_s256 emitted as a string when set")]
    public async Task AuthToken_EmitsMission_WhenSet()
    {
        var payload = PayloadOf(await AuthTokenAsync(AAuthKey.Generate(), AAuthKey.Generate(), S256));
        Assert.Equal(S256, (string?)payload["mission_s256"]);
        Assert.False(payload.ContainsKey("mission"));
    }

    [Fact(DisplayName = "§Person Token Structure — mission_s256 emitted as a string when set")]
    public async Task PersonToken_EmitsMission_WhenSet()
    {
        var payload = PayloadOf(await new PersonTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = Aud,
            Audience = Iss,
            Subject = "person-1",
            ConfirmationKey = AAuthKey.Generate(),
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Key = AAuthKey.Generate(),
            KeyId = "p1",
            MissionS256 = S256,
        }.BuildAsync());
        Assert.Equal(S256, (string?)payload["mission_s256"]);
    }

    [Theory(DisplayName = "§Missions — builders reject a malformed mission_s256")]
    [InlineData("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=")]   // padded
    [InlineData("tooshort")]                                      // not 32 bytes
    [InlineData("47DEQpj8HBSa+_TImW/5JCeuQeRkm5NMpJWZG3hSuFU")]   // standard base64 (+,/)
    public async Task Builders_RejectMalformedMission(string s256)
    {
        await Assert.ThrowsAsync<System.InvalidOperationException>(async () => await ResourceTokenAsync(s256));
        await Assert.ThrowsAsync<System.InvalidOperationException>(async () => await AuthTokenAsync(AAuthKey.Generate(), AAuthKey.Generate(), s256));
    }

    [Fact(DisplayName = "§Auth Token Verification — VerifiedToken.MissionS256 surfaces the verified claim")]
    public async Task VerifiedToken_SurfacesMission()
    {
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var verified = new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(
            await AuthTokenAsync(issuerKey, agentKey, S256), issuerKey, Iss, agentKey);

        Assert.Equal(S256, verified.MissionS256);
    }

    [Fact(DisplayName = "§Auth Token Verification — VerifiedToken.MissionS256 is null when absent")]
    public async Task VerifiedToken_MissionNull_WhenAbsent()
    {
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var verified = new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(
            await AuthTokenAsync(issuerKey, agentKey, null), issuerKey, Iss, agentKey);

        Assert.Null(verified.MissionS256);
    }

    [Theory(DisplayName = "§Missions — MissionReference rejects a malformed mission_s256")]
    [InlineData("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=")]
    [InlineData("tooshort")]
    [InlineData("47DEQpj8HBSa+_TImW/5JCeuQeRkm5NMpJWZG3hSuFU")]
    [InlineData("")]
    public void MissionReference_RejectsMalformed(string s256)
    {
        Assert.False(MissionReference.IsValid(s256));
        Assert.Throws<TokenVerificationException>(() => MissionReference.Read(new JsonObject { ["mission_s256"] = s256 }));
    }

    [Fact(DisplayName = "§Missions — MissionReference accepts a conformant mission_s256")]
    public void MissionReference_AcceptsConformant()
    {
        Assert.True(MissionReference.IsValid(S256));
        Assert.Equal(S256, MissionReference.Read(new JsonObject { ["mission_s256"] = S256 }));
        Assert.Null(MissionReference.Read(new JsonObject()));
        Assert.Throws<TokenVerificationException>(() => MissionReference.Read(new JsonObject
        {
            ["mission_s256"] = new JsonObject { ["approver"] = Aud, ["s256"] = S256 },
        }));
    }
}

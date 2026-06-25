using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the optional <c>mission</c> claim ({approver, s256}) carried in
/// resource and auth tokens (§Resource Token Structure, §Auth Token Structure).
/// </summary>
public class MissionClaimTests
{
    private const string Iss = "https://resource.example";
    private const string Aud = "https://ps.example";
    private const string Agent = "aauth:alice@ap.example";
    private const string Approver = "https://ps.example";
    private const string S256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    private static JsonObject PayloadOf(string jwt)
    {
        var parts = jwt.Split('.');
        return (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!;
    }

    [Fact(DisplayName = "§Resource Token Structure — mission omitted when not set")]
    public void ResourceToken_OmitsMission_WhenNotSet()
    {
        var jwt = new ResourceTokenBuilder
        {
            Issuer = Iss,
            Audience = Aud,
            Agent = Agent,
            AgentJkt = "thumb",
            Key = AAuthKey.Generate(),
            KeyId = "r1",
            Scope = "whoami",
        }.Build();

        Assert.False(PayloadOf(jwt).ContainsKey("mission"));
    }

    [Fact(DisplayName = "§Resource Token Structure — mission emitted as {approver, s256} when set")]
    public void ResourceToken_EmitsMission_WhenSet()
    {
        var jwt = new ResourceTokenBuilder
        {
            Issuer = Iss,
            Audience = Aud,
            Agent = Agent,
            AgentJkt = "thumb",
            Key = AAuthKey.Generate(),
            KeyId = "r1",
            Scope = "whoami",
            Mission = new MissionClaim(Approver, S256),
        }.Build();

        var mission = PayloadOf(jwt)["mission"] as JsonObject;
        Assert.NotNull(mission);
        Assert.Equal(Approver, (string?)mission!["approver"]);
        Assert.Equal(S256, (string?)mission["s256"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — mission omitted when not set")]
    public void AuthToken_OmitsMission_WhenNotSet()
    {
        var jwt = new AuthTokenBuilder
        {
            Issuer = Aud,
            Audience = Iss,
            Agent = Agent,
            AgentConfirmationKey = AAuthKey.Generate(),
            Key = AAuthKey.Generate(),
            KeyId = "p1",
            Scope = "whoami",
        }.Build();

        Assert.False(PayloadOf(jwt).ContainsKey("mission"));
    }

    [Fact(DisplayName = "§Auth Token Structure — mission emitted as {approver, s256} when set")]
    public void AuthToken_EmitsMission_WhenSet()
    {
        var jwt = new AuthTokenBuilder
        {
            Issuer = Aud,
            Audience = Iss,
            Agent = Agent,
            AgentConfirmationKey = AAuthKey.Generate(),
            Key = AAuthKey.Generate(),
            KeyId = "p1",
            Scope = "whoami",
            Mission = new MissionClaim(Approver, S256),
        }.Build();

        var mission = PayloadOf(jwt)["mission"] as JsonObject;
        Assert.NotNull(mission);
        Assert.Equal(Approver, (string?)mission!["approver"]);
        Assert.Equal(S256, (string?)mission["s256"]);
    }

    [Fact(DisplayName = "§Auth Token Verification — VerifiedToken.Mission surfaces the verified claim")]
    public void VerifiedToken_SurfacesMission()
    {
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = new AuthTokenBuilder
        {
            Issuer = Aud,
            Audience = Iss,
            Agent = Agent,
            AgentConfirmationKey = agentKey,
            Key = issuerKey,
            KeyId = "p1",
            Scope = "whoami",
            Mission = new MissionClaim(Approver, S256),
        }.Build();

        var verified = new TokenVerifier().VerifyAuthToken(
            jwt, issuerKey, Iss, agentKey, Agent);

        Assert.NotNull(verified.Mission);
        Assert.Equal(Approver, verified.Mission!.Approver);
        Assert.Equal(S256, verified.Mission.S256);
    }

    [Fact(DisplayName = "§Auth Token Verification — VerifiedToken.Mission is null when absent")]
    public void VerifiedToken_MissionNull_WhenAbsent()
    {
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = new AuthTokenBuilder
        {
            Issuer = Aud,
            Audience = Iss,
            Agent = Agent,
            AgentConfirmationKey = agentKey,
            Key = issuerKey,
            KeyId = "p1",
            Scope = "whoami",
        }.Build();

        var verified = new TokenVerifier().VerifyAuthToken(
            jwt, issuerKey, Iss, agentKey, Agent);

        Assert.Null(verified.Mission);
    }

    [Theory(DisplayName = "§Mission Reference — FromPayload rejects a malformed approver or s256")]
    [InlineData("http://ps.example", S256)]                                   // non-https approver
    [InlineData("https://ps.example/path", S256)]                             // approver has a path
    [InlineData("https://ps.example:8443", S256)]                             // approver has a port
    [InlineData(Approver, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=")]    // padded s256
    [InlineData(Approver, "tooshort")]                                        // wrong-length s256
    [InlineData(Approver, "47DEQpj8HBSa+_TImW/5JCeuQeRkm5NMpJWZG3hSuFU")]     // non-url base64 chars
    public void FromPayload_RejectsMalformedReference(string approver, string s256)
    {
        var payload = new JsonObject
        {
            ["mission"] = new JsonObject { ["approver"] = approver, ["s256"] = s256 },
        };
        Assert.Null(MissionClaim.FromPayload(payload));
    }

    [Fact(DisplayName = "§Mission Reference — FromPayload accepts a conformant reference")]
    public void FromPayload_AcceptsConformantReference()
    {
        var payload = new JsonObject
        {
            ["mission"] = new JsonObject { ["approver"] = Approver, ["s256"] = S256 },
        };
        var claim = MissionClaim.FromPayload(payload);
        Assert.NotNull(claim);
        Assert.Equal(Approver, claim!.Approver);
        Assert.Equal(S256, claim.S256);
    }
}

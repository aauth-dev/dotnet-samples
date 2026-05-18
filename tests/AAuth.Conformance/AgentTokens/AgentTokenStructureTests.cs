using System;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.AgentTokens;

/// <summary>
/// Issuer-side conformance for an <c>aa-agent+jwt</c> per
/// draft-hardt-oauth-aauth-protocol-01 §Agent Token Structure.
/// </summary>
/// <remarks>
/// Receiver-side clauses (§Agent Token Verification) are covered separately
/// by the verifier-side conformance tests.
/// </remarks>
public class AgentTokenStructureTests
{
    private const string Iss = "https://ap.example";
    private const string Sub = "aauth:alice@ap.example";
    private const string Kid = "k1";

    private static AAuthKey NewKey() => AAuthKey.Generate();

    private static AgentTokenBuilder Builder(AAuthKey key) => new()
    {
        Issuer = Iss,
        Subject = Sub,
        KeyId = Kid,
        Key = key,
    };

    private static (JsonObject Header, JsonObject Payload) Decode(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        var header = JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!.AsObject();
        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!.AsObject();
        return (header, payload);
    }

    // -- Header --

    /// <summary>
    /// "Header: alg: Signing algorithm. EdDSA is RECOMMENDED."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — header.alg SHOULD be EdDSA")]
    public void HeaderAlg_IsEdDsa()
    {
        var (header, _) = Decode(Builder(NewKey()).Build());
        Assert.Equal("EdDSA", (string?)header["alg"]);
    }

    /// <summary>
    /// "Header: alg: ... Implementations MUST NOT accept `none`."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — header.alg MUST NOT be 'none'")]
    public void HeaderAlg_NeverNone()
    {
        var (header, _) = Decode(Builder(NewKey()).Build());
        Assert.NotEqual("none", ((string?)header["alg"])?.ToLowerInvariant());
    }

    /// <summary>
    /// "Header: typ: aa-agent+jwt"
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — header.typ MUST be aa-agent+jwt")]
    public void HeaderTyp_IsAgentTokenMediaType()
    {
        var (header, _) = Decode(Builder(NewKey()).Build());
        Assert.Equal("aa-agent+jwt", (string?)header["typ"]);
    }

    /// <summary>
    /// "Header: kid: Key identifier"
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — header.kid MUST be present")]
    public void HeaderKid_IsPresent()
    {
        var (header, _) = Decode(Builder(NewKey()).Build());
        Assert.Equal(Kid, (string?)header["kid"]);
    }

    // -- Required payload claims --

    [Fact(DisplayName = "§Agent Token Structure — payload.iss MUST be the agent provider URL")]
    public void PayloadIss_IsAgentProviderUrl()
    {
        var (_, payload) = Decode(Builder(NewKey()).Build());
        Assert.Equal(Iss, (string?)payload["iss"]);
    }

    /// <summary>
    /// "dwk: aauth-agent.json — the well-known metadata document name for key
    /// discovery"
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — payload.dwk MUST equal 'aauth-agent.json'")]
    public void PayloadDwk_IsAgentWellKnownName()
    {
        var (_, payload) = Decode(Builder(NewKey()).Build());
        Assert.Equal("aauth-agent.json", (string?)payload["dwk"]);
    }

    [Fact(DisplayName = "§Agent Token Structure — payload.sub MUST be the agent identifier")]
    public void PayloadSub_IsAgentIdentifier()
    {
        var (_, payload) = Decode(Builder(NewKey()).Build());
        Assert.Equal(Sub, (string?)payload["sub"]);
    }

    /// <summary>
    /// "jti: Unique token identifier for replay detection, audit, and
    /// revocation"
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — payload.jti MUST be unique per token")]
    public void PayloadJti_IsUniquePerToken()
    {
        var key = NewKey();
        var (_, a) = Decode(Builder(key).Build());
        var (_, b) = Decode(Builder(key).Build());

        var jtiA = (string?)a["jti"];
        Assert.False(string.IsNullOrEmpty(jtiA));
        Assert.NotEqual(jtiA, (string?)b["jti"]);
    }

    /// <summary>
    /// "cnf: Confirmation claim (RFC 7800) with `jwk` containing the agent's
    /// public key"
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — payload.cnf.jwk MUST embed the agent public key")]
    public void PayloadCnfJwk_EmbedsAgentPublicKey()
    {
        var key = NewKey();
        var (_, payload) = Decode(Builder(key).Build());

        var jwk = payload["cnf"]?["jwk"]?.AsObject();
        Assert.NotNull(jwk);
        Assert.Equal("OKP", (string?)jwk["kty"]);
        Assert.Equal("Ed25519", (string?)jwk["crv"]);
        Assert.Equal(Base64UrlEncoder.Encode(key.PublicKeyBytes), (string?)jwk["x"]);
        Assert.Null(jwk["d"]); // private half MUST NOT leak
    }

    [Fact(DisplayName = "§Agent Token Structure — payload.iat MUST be set")]
    public void PayloadIat_IsSet()
    {
        var (_, payload) = Decode(Builder(NewKey()).Build());
        Assert.NotNull((long?)payload["iat"]);
    }

    [Fact(DisplayName = "§Agent Token Structure — payload.exp MUST be after iat")]
    public void PayloadExp_IsAfterIat()
    {
        var (_, payload) = Decode(Builder(NewKey()).Build());
        Assert.True((long?)payload["exp"] > (long?)payload["iat"]);
    }

    /// <summary>
    /// "Agent tokens SHOULD NOT have a lifetime exceeding 24 hours."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — agent token lifetime SHOULD NOT exceed 24h")]
    public void AgentTokenLifetime_DoesNotExceedRecommendedMax()
    {
        var (_, payload) = Decode(Builder(NewKey()).Build());
        var lifetime = (long)payload["exp"]! - (long)payload["iat"]!;
        Assert.InRange(lifetime, 1, (long)TimeSpan.FromHours(24).TotalSeconds);
    }

    // -- Optional payload claims --

    /// <summary>
    /// "ps: The HTTPS URL of the agent's person server. Configured per agent
    /// instance."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — payload.ps is included when configured")]
    public void PayloadPs_IncludedWhenConfigured()
    {
        var jwt = new AgentTokenBuilder
        {
            Issuer = Iss,
            Subject = Sub,
            KeyId = Kid,
            Key = NewKey(),
            PersonServer = "https://ps.example",
        }.Build();

        var (_, payload) = Decode(jwt);
        Assert.Equal("https://ps.example", (string?)payload["ps"]);
    }

    [Fact(DisplayName = "§Agent Token Structure — payload.ps is absent when not configured")]
    public void PayloadPs_AbsentByDefault()
    {
        var (_, payload) = Decode(Builder(NewKey()).Build());
        Assert.Null(payload["ps"]);
    }

    // -- Signature integrity (issuer-side guarantee) --

    /// <summary>
    /// The token signature MUST verify against the public key embedded in
    /// <c>cnf.jwk</c>; otherwise verifiers cannot bind the request to the
    /// agent (§Agent Token Verification step 5).
    /// </summary>
    [Fact(DisplayName = "§Agent Token Structure — signature verifies against cnf.jwk")]
    public void Signature_VerifiesAgainstEmbeddedCnfJwk()
    {
        var jwt = Builder(NewKey()).Build();
        var parts = jwt.Split('.');
        var (_, payload) = Decode(jwt);

        var pub = AAuthKey.FromJwk(payload["cnf"]!["jwk"]!.AsObject());
        var signature = Base64UrlEncoder.DecodeBytes(parts[2]);
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);

        Assert.True(pub.Verify(signingInput, signature));
    }
}

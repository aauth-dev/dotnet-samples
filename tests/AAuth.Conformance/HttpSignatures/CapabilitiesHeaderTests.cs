using System;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance tests for AAuth-Capabilities header (§14.1).
/// </summary>
public class CapabilitiesHeaderTests
{
    [Fact(DisplayName = "§14.1 — AAuth-Capabilities header formats correctly")]
    public void Format_MultipleCapabilities()
    {
        var value = AAuthCapabilitiesHeader.Format("interaction", "clarification", "payment");
        Assert.Equal("interaction, clarification, payment", value);
    }

    [Fact(DisplayName = "§14.1 — AAuth-Capabilities header parses correctly")]
    public void Parse_MultipleCapabilities()
    {
        var caps = AAuthCapabilitiesHeader.Parse("interaction, clarification, payment");
        Assert.Equal(3, caps.Count);
        Assert.Contains("interaction", caps);
        Assert.Contains("clarification", caps);
        Assert.Contains("payment", caps);
    }

    [Fact(DisplayName = "§14.1 — AAuth-Capabilities empty value parses to empty list")]
    public void Parse_Empty()
    {
        var caps = AAuthCapabilitiesHeader.Parse("");
        Assert.Empty(caps);
    }

    [Fact(DisplayName = "§14.1 — AAuthSigningHandler emits Capabilities header when configured")]
    public void SigningHandler_EmitsCapabilities()
    {
        var key = AAuthKey.Generate();
        var token = new AAuth.Tokens.AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            Key = key,
            KeyId = "k1",
            PersonServer = "https://ps.example",
        }.Build();

        var handler = new AAuthSigningHandler(key, () => token)
        {
            Capabilities = new[] { "interaction", "mission" },
        };

        var request = new System.Net.Http.HttpRequestMessage(
            System.Net.Http.HttpMethod.Get,
            "https://resource.example/api");

        handler.Sign(request);

        Assert.True(request.Headers.Contains(AAuthCapabilitiesHeader.Name));
        var headerValue = string.Join(", ", request.Headers.GetValues(AAuthCapabilitiesHeader.Name));
        Assert.Contains("interaction", headerValue);
        Assert.Contains("mission", headerValue);
    }

    [Fact(DisplayName = "§14.1 — AAuthSigningHandler does not emit Capabilities header when not configured")]
    public void SigningHandler_NoCapabilities_NoHeader()
    {
        var key = AAuthKey.Generate();
        var token = new AAuth.Tokens.AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            Key = key,
            KeyId = "k1",
            PersonServer = "https://ps.example",
        }.Build();

        var handler = new AAuthSigningHandler(key, () => token);
        var request = new System.Net.Http.HttpRequestMessage(
            System.Net.Http.HttpMethod.Get,
            "https://resource.example/api");

        handler.Sign(request);

        Assert.False(request.Headers.Contains(AAuthCapabilitiesHeader.Name));
    }
}

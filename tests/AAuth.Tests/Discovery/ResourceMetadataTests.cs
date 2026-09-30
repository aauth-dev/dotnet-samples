using System.Text.Json.Nodes;
using AAuth.Discovery;
using Xunit;

namespace AAuth.Tests.Discovery;

/// <summary>
/// Unit coverage for <see cref="ResourceMetadata"/> parsing of the draft-02
/// <c>access_mode</c> field and the relaxed (optional) <c>jwks_uri</c>.
/// </summary>
public class ResourceMetadataTests
{
    [Fact(DisplayName = "§Resource Metadata — parses access_mode when present")]
    public void FromJson_ParsesAccessMode()
    {
        var doc = new JsonObject
        {
            ["issuer"] = "https://resource.example",
            ["jwks_uri"] = "https://resource.example/.well-known/jwks.json",
            ["access_mode"] = "auth-token",
        };

        var meta = ResourceMetadata.FromJson(doc);

        Assert.Equal("auth-token", meta.AccessMode);
        Assert.Equal("https://resource.example/.well-known/jwks.json", meta.JwksUri);
    }

    [Fact(DisplayName = "§Resource Metadata — access_mode is null when absent (spec default agent-token)")]
    public void FromJson_AccessModeNullWhenAbsent()
    {
        var doc = new JsonObject { ["issuer"] = "https://resource.example" };

        var meta = ResourceMetadata.FromJson(doc);

        Assert.Null(meta.AccessMode);
    }

    [Fact(DisplayName = "§Resource Metadata — jwks_uri is optional (identity-only resource omits it)")]
    public void FromJson_AllowsMissingJwksUri()
    {
        var doc = new JsonObject
        {
            ["issuer"] = "https://resource.example",
            ["access_mode"] = "agent-token",
        };

        var meta = ResourceMetadata.FromJson(doc);

        Assert.Null(meta.JwksUri);
        Assert.Equal("agent-token", meta.AccessMode);
        Assert.Equal("https://resource.example", meta.Issuer);
    }

    [Fact(DisplayName = "§Resource Metadata — parses optional Markdown description")]
    public void FromJson_ParsesDescription()
    {
        var doc = new JsonObject
        {
            ["issuer"] = "https://resource.example",
            ["description"] = "**Example Data Service** stores your documents.",
        };

        var meta = ResourceMetadata.FromJson(doc);

        Assert.Equal("**Example Data Service** stores your documents.", meta.Description);
    }

    [Fact(DisplayName = "§Resource Metadata — parses additional_signature_components")]
    public void FromJson_ParsesAdditionalSignatureComponents()
    {
        var doc = new JsonObject
        {
            ["issuer"] = "https://resource.example",
            ["additional_signature_components"] = new JsonArray { " Content-Type ", "@QUERY", "content-type" },
        };

        var meta = ResourceMetadata.FromJson(doc);

        Assert.Equal(new[] { "content-type", "@query" }, meta.AdditionalSignatureComponents);
    }

    [Theory(DisplayName = "§Resource Metadata — rejects malformed additional_signature_components")]
    [InlineData("blank")]
    [InlineData("non-string")]
    [InlineData("not-array")]
    public void FromJson_RejectsMalformedAdditionalSignatureComponents(string variant)
    {
        JsonNode malformed = variant switch
        {
            "blank" => new JsonArray { "content-type", " " },
            "non-string" => new JsonArray { "content-type", 42 },
            _ => "content-type",
        };
        var doc = new JsonObject
        {
            ["issuer"] = "https://resource.example",
            ["additional_signature_components"] = malformed,
        };

        Assert.Throws<InvalidOperationException>(() => ResourceMetadata.FromJson(doc));
    }
}

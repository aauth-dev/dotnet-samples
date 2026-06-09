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
}

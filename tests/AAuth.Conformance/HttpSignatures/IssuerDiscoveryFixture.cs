using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;

namespace AAuth.Conformance.HttpSignatures;

internal sealed class IssuerDiscoveryFixture(string issuer, IAAuthKey key, string kid) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri!.GetLeftPart(UriPartial.Authority) != issuer)
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        var jwk = key.ToPublicJwk();
        jwk["kid"] = kid;
        var document = request.RequestUri.AbsolutePath.EndsWith("/keys", StringComparison.Ordinal)
            ? new JsonObject { ["keys"] = new JsonArray(jwk) }
            : new JsonObject { ["issuer"] = issuer, ["jwks_uri"] = issuer + "/keys" };
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(document) });
    }
}
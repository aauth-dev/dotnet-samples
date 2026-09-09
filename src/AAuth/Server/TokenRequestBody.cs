using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

public static class TokenRequestBody
{
    public static async Task<JsonObject> ReadAsync(HttpRequest request, TokenVerifier verifier)
    {
        var json = await request.ReadFromJsonAsync<JsonElement>(request.HttpContext.RequestAborted);
        var body = SignatureKeyParser.ParseJsonObject(Encoding.UTF8.GetBytes(json.GetRawText()));
        foreach (var (field, credential, type) in new[]
        {
            ("agent_token", TokenCredential.Agent, AgentTokenBuilder.TokenType),
            ("resource_token", TokenCredential.Resource, ResourceTokenBuilder.TokenType),
            ("subagent_token", TokenCredential.Subagent, AgentTokenBuilder.TokenType),
            ("upstream_token", TokenCredential.Upstream, AuthTokenBuilder.TokenType),
        })
        {
            if (body[field] is not { } node) continue;
            if (node is not JsonValue value || !value.TryGetValue<string>(out var token))
                throw new JsonException($"{field} must be a string.");
            try { verifier.ReadStructure(token, type); }
            catch (TokenVerificationException exception)
            { throw new TokenVerificationException(exception.Message, exception) { Credential = credential }; }
        }
        return body;
    }
}
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

public static class TokenRequestBody
{
    public static async Task<JsonObject> ReadAsync(HttpRequest request, TokenVerifier verifier)
    {
        var body = await ReadJsonAsync(request);
        ValidateCredentials(body, verifier);
        return body;
    }

    internal static async Task<JsonObject> ReadJsonAsync(HttpRequest request)
    {
        if (!request.HasJsonContentType()) throw new JsonException("Expected a JSON request body.");
        var json = await request.ReadFromJsonAsync<JsonElement>(request.HttpContext.RequestAborted);
        return SignatureKeyParser.ParseJsonObject(Encoding.UTF8.GetBytes(json.GetRawText()));
    }

    internal static void ValidateCredentials(JsonObject body, TokenVerifier verifier)
    {
        foreach (var (field, credential, types) in new[]
        {
            ("agent_token", TokenCredential.Agent, new[] { AgentTokenBuilder.TokenType }),
            ("resource_token", TokenCredential.Resource, new[] { ResourceTokenBuilder.TokenType }),
            ("subagent_token", TokenCredential.Subagent, new[] { AgentTokenBuilder.TokenType }),
            ("presented_token", TokenCredential.Presented, new[] { PersonTokenBuilder.TokenType, AuthTokenBuilder.TokenType }),
            ("upstream_token", TokenCredential.Upstream, new[] { PersonTokenBuilder.TokenType, AuthTokenBuilder.TokenType }),
        })
        {
            if (body[field] is not { } node) continue;
            if (node is not JsonValue value || !value.TryGetValue<string>(out var token))
                throw new JsonException($"{field} must be a string.");
            try
            {
                var typ = (string?)TokenVerifier.DecodeJsonSegment(token.Split('.')[0], "header")["typ"];
                if (Array.IndexOf(types, typ) < 0)
                    throw new TokenVerificationException($"{field} has an unexpected typ.");
                verifier.ReadStructure(token, typ!);
            }
            catch (TokenVerificationException exception)
            { throw new TokenVerificationException(exception.Message, exception) { Credential = credential }; }
        }
    }
}
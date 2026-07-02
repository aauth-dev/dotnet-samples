using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Headers;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Composes and sends R3 operation requests to a resource authorization endpoint.</summary>
public static class R3Request
{
    public static JsonObject CreateBody(R3Operations operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        operations.Validate();
        return new JsonObject
        {
            ["r3_operations"] = R3ClaimJson.GrantToJson(operations.ToGrant()),
        };
    }

    public static R3Operations CreateMcpOperations(params string[] tools) => R3Operations.Mcp(tools);

    public static R3Operations CreateOpenApiOperations(params string[] operationIds) => R3Operations.OpenApi(operationIds);

    public static async Task<HttpResponseMessage> PostAuthorizeAsync(
        HttpClient http,
        string authorizationEndpoint,
        R3Operations operations,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentException.ThrowIfNullOrEmpty(authorizationEndpoint);
        return await http.PostAsJsonAsync(authorizationEndpoint, CreateBody(operations), cancellationToken).ConfigureAwait(false);
    }

    public static R3ChallengeInfo? ReadChallenge(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values))
        {
            return null;
        }
        var header = values.FirstOrDefault();
        if (header is null)
        {
            return null;
        }
        var parsed = AAuthRequirementHeader.Parse(header);
        return parsed.ResourceToken is null ? null : new R3ChallengeInfo(parsed.Requirement, parsed.ResourceToken);
    }
}

public sealed record R3ChallengeInfo(string Requirement, string ResourceToken);

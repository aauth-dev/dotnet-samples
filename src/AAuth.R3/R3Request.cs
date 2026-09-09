using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Headers;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Composes and sends R3 operation requests to a resource authorization endpoint.</summary>
public static class R3Request
{
    public static R3Operations ReadOperations(JsonObject body, R3VocabularySchemas? schemas = null)
    {
        ArgumentNullException.ThrowIfNull(body);
        var grant = R3ClaimReader.ReadGrant(body["r3_operations"], schemas)
            ?? throw new InvalidOperationException("r3_operations is required.");
        grant.Validate(schemas: schemas);
        return new R3Operations { Vocabulary = grant.Vocabulary, Operations = grant.Operations };
    }

    public static JsonObject CreateBody(R3Operations operations, string? account = null, R3VocabularySchemas? schemas = null)
    {
        ArgumentNullException.ThrowIfNull(operations);
        operations.Validate(schemas);
        AAuth.Tokens.AccountBinding.Validate(account);
        var body = new JsonObject
        {
            ["r3_operations"] = R3ClaimJson.GrantToJson(operations.ToGrant()),
        };
        if (account is not null) body["account"] = account;
        return body;
    }

    public static R3Operations CreateMcpOperations(params string[] tools) => R3Operations.Mcp(tools);

    public static R3Operations CreateOpenApiOperations(params string[] operationIds) => R3Operations.OpenApi(operationIds);

    public static async Task<HttpResponseMessage> PostAuthorizeAsync(
        HttpClient http,
        string authorizationEndpoint,
        R3Operations operations,
        CancellationToken cancellationToken = default,
        string? account = null,
        R3VocabularySchemas? schemas = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentException.ThrowIfNullOrEmpty(authorizationEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Post, authorizationEndpoint)
        {
            Content = JsonContent.Create(CreateBody(operations, account, schemas)),
        };
        if (account is not null) request.Options.Set(AAuth.Agent.AAuthRequestOptions.Account, account);
        return await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
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

using System.Text.Json;
using System.Text.Json.Nodes;

namespace AAuth.R3.Model;

public sealed record R3OperationIdentity(string Vocabulary, R3Operation Operation)
{
    public static R3OperationIdentity OpenApi(string operationId) => new(Model.Vocabulary.OpenApi, R3Operation.OpenApi(operationId));
    public static R3OperationIdentity Mcp(string tool) => new(Model.Vocabulary.Mcp, R3Operation.Mcp(tool));

    public bool Matches(string vocabulary, R3Operation operation) =>
        string.Equals(Vocabulary, vocabulary, StringComparison.Ordinal) &&
        JsonNode.DeepEquals(ToIdentityJson(Operation), ToIdentityJson(operation));

    public bool Covers(R3OperationIdentity requested)
    {
        if (Vocabulary != Model.Vocabulary.OData || requested.Vocabulary != Vocabulary ||
            Operation.Methods is null || requested.Operation.Methods is null)
            return Matches(requested.Vocabulary, requested.Operation);
        return new R3OperationIdentity(Vocabulary, Operation with { Methods = null })
            .Matches(requested.Vocabulary, requested.Operation with { Methods = null }) &&
            requested.Operation.Methods.All(method => Operation.Methods.Contains(method, StringComparer.Ordinal));
    }

    private static JsonNode? ToIdentityJson(R3Operation operation) =>
        JsonSerializer.SerializeToNode(operation.Methods is null ? operation : operation with
        {
            Methods = operation.Methods.Order(StringComparer.Ordinal).ToArray(),
        }, R3Json.Options);
}
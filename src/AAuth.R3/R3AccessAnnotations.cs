using System.Text.Json.Nodes;
using AAuth.R3.Model;
using Modes = AAuth.AAuthConstants.AccessModes;

namespace AAuth.R3;

/// <summary>An operation access annotation: the credential one operation requires and whether it draws down a budget.</summary>
/// <param name="AccessMode">An <c>access_mode</c> value, or <see langword="null"/> to take the resource default.</param>
/// <param name="Budget">Whether invoking the operation draws down a budget. Read and written as an
/// annotation only; this SDK does not implement budget accounting or enforcement, so a flagged
/// operation only raises its access-mode floor to <c>auth-token</c>.</param>
public sealed record R3OperationAccess(string? AccessMode, bool Budget = false);

/// <summary>
/// Writes and reads R3 operation access annotations (R3 #operation-access-annotations) in the
/// vocabulary document an agent already reads. Annotations are advisory: resources enforce the
/// presented credential, and agents must still handle any runtime <c>AAuth-Requirement</c>.
/// </summary>
public static class R3AccessAnnotations
{
    public const string OpenApiAccessMode = "x-aauth-access-mode";
    public const string OpenApiBudget = "x-aauth-budget";
    public const string McpMeta = "_meta";
    public const string McpAccessMode = "aauth.dev/access-mode";
    public const string McpBudget = "aauth.dev/budget";
    public const string ODataAccessMode = "AAuth.AccessMode";
    public const string ODataBudget = "AAuth.Budget";

    /// <summary>
    /// Annotates an OpenAPI or AsyncAPI Operation Object, or an MCP Tool (in its <c>_meta</c>).
    /// OData annotations live in <c>$metadata</c> XML under <see cref="ODataAccessMode"/> and
    /// <see cref="ODataBudget"/>; gRPC, GraphQL and WSDL have no encoding.
    /// </summary>
    public static JsonObject Annotate(JsonObject definition, string vocabulary, R3OperationAccess access)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(access);
        Validate(access);
        var (target, modeKey, budgetKey) = Target(definition, vocabulary, create: true);
        if (access.AccessMode is not null) target![modeKey] = access.AccessMode;
        if (access.Budget) target![budgetKey] = true;
        return definition;
    }

    /// <summary>Reads an annotation, or <see langword="null"/> when the operation carries none. Unrecognized access modes are ignored.</summary>
    public static R3OperationAccess? Read(JsonObject definition, string vocabulary)
    {
        ArgumentNullException.ThrowIfNull(definition);
        var (target, modeKey, budgetKey) = Target(definition, vocabulary, create: false);
        if (target is null) return null;
        var mode = target[modeKey] is JsonValue modeValue && modeValue.TryGetValue<string>(out var text) && IsAnnotationMode(text) ? text : null;
        var budget = target[budgetKey] is JsonValue budgetValue && budgetValue.TryGetValue<bool>(out var flag) && flag;
        return mode is null && !budget ? null : new R3OperationAccess(mode, budget);
    }

    /// <summary>
    /// The credential an agent should plan for: the annotation replaces the resource's
    /// <c>access_mode</c> (default <c>agent-token</c>), and a budget requires at least an auth token.
    /// </summary>
    public static string EffectiveAccessMode(R3OperationAccess? annotation, string? resourceAccessMode)
    {
        if (annotation is { Budget: true, AccessMode: null or Modes.AgentToken or Modes.PersonToken })
            return Modes.AuthToken;
        return annotation?.AccessMode ?? resourceAccessMode ?? Modes.AgentToken;
    }

    private static void Validate(R3OperationAccess access)
    {
        if (access.AccessMode is not null && !IsAnnotationMode(access.AccessMode))
            throw new InvalidOperationException(
                $"Access mode annotations must be 'agent-token', 'person-token', 'auth-token', or 'per-call' (was '{access.AccessMode}').");
        if (access.Budget && access.AccessMode is Modes.AgentToken or Modes.PersonToken)
            throw new InvalidOperationException("A budget annotation requires at least an auth token.");
    }

    private static bool IsAnnotationMode(string mode) =>
        mode is Modes.AgentToken or Modes.PersonToken or Modes.AuthToken or Modes.PerCall;

    private static (JsonObject? Target, string ModeKey, string BudgetKey) Target(JsonObject definition, string vocabulary, bool create)
    {
        switch (vocabulary)
        {
            case Vocabulary.OpenApi or Vocabulary.AsyncApi:
                return (definition, OpenApiAccessMode, OpenApiBudget);
            case Vocabulary.Mcp:
                if (definition[McpMeta] is JsonObject meta) return (meta, McpAccessMode, McpBudget);
                if (!create) return (null, McpAccessMode, McpBudget);
                meta = new JsonObject();
                definition[McpMeta] = meta;
                return (meta, McpAccessMode, McpBudget);
            default:
                throw new InvalidOperationException($"R3 defines no JSON annotation encoding for '{vocabulary}'.");
        }
    }
}

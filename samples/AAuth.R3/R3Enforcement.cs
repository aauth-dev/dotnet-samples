using System.Text.Json.Nodes;
using AAuth.R3.Model;
using Microsoft.AspNetCore.Http;

namespace AAuth.R3;

/// <summary>Evaluates R3 grants and conditional proposal retries for resource calls.</summary>
public sealed class R3Enforcement
{
    private readonly R3ProposalStore _proposalStore;
    private readonly Uri _resourceBaseUri;
    private readonly string _proposalPathPrefix;

    public R3Enforcement(R3ProposalStore proposalStore, Uri resourceBaseUri, string proposalPathPrefix = "/r3/proposals")
    {
        _proposalStore = proposalStore;
        _resourceBaseUri = resourceBaseUri;
        _proposalPathPrefix = proposalPathPrefix;
    }

    public R3EnforcementDecision Evaluate(
        R3ClaimReader.AuthTokenClaims claims,
        string tool,
        IReadOnlyDictionary<string, R3Parameter>? parameters = null,
        Func<string, IReadOnlyDictionary<string, R3Parameter>, R3Display?>? displayFactory = null,
        string? approvedProposalS256 = null)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentException.ThrowIfNullOrEmpty(tool);

        if (claims.Granted.ContainsTool(tool))
        {
            return R3EnforcementDecision.Granted();
        }

        if (!claims.Conditional?.ContainsTool(tool) ?? true)
        {
            return R3EnforcementDecision.Rejected("operation_not_granted");
        }

        if (approvedProposalS256 is not null)
        {
            if (parameters is null || !_proposalStore.TryGet(approvedProposalS256, out var stored))
            {
                return R3EnforcementDecision.Rejected("unknown_proposal");
            }
            var expected = R3ProposalDocument.FromUtf8Bytes(stored);
            var actual = new R3ProposalDocument
            {
                Version = expected.Version,
                Vocabulary = expected.Vocabulary,
                Operations = expected.Operations,
                Parameters = parameters,
                Display = expected.Display,
            };
            var actualHash = R3Hash.ComputeS256(actual.ToUtf8Bytes());
            return string.Equals(actualHash, approvedProposalS256, StringComparison.Ordinal)
                ? R3EnforcementDecision.Granted()
                : R3EnforcementDecision.Rejected("proposal_digest_mismatch");
        }

        var proposalParams = parameters ?? new Dictionary<string, R3Parameter>(StringComparer.Ordinal);
        if (proposalParams.Count == 0)
        {
            return R3EnforcementDecision.Rejected("parameters_required");
        }

        var proposal = new R3ProposalDocument
        {
            Version = "v02",
            Vocabulary = Vocabulary.Mcp,
            Operations = [new McpOperation { Tool = tool }],
            Parameters = proposalParams,
            Display = displayFactory?.Invoke(tool, proposalParams),
        };
        var storedProposal = _proposalStore.Add(proposal, _resourceBaseUri, _proposalPathPrefix);
        return R3EnforcementDecision.Conditional(storedProposal.Uri, storedProposal.S256);
    }

    public R3EnforcementDecision Evaluate(JsonObject verifiedAuthTokenPayload, string tool, IReadOnlyDictionary<string, R3Parameter>? parameters = null, string? approvedProposalS256 = null) =>
        Evaluate(R3ClaimReader.ReadAuthToken(verifiedAuthTokenPayload), tool, parameters, approvedProposalS256: approvedProposalS256);
}

public sealed record R3EnforcementDecision(R3EnforcementDecisionKind Kind, string? ProposalUri = null, string? ProposalS256 = null, string? Error = null)
{
    public static R3EnforcementDecision Granted() => new(R3EnforcementDecisionKind.Granted);
    public static R3EnforcementDecision Conditional(string proposalUri, string proposalS256) => new(R3EnforcementDecisionKind.Conditional, proposalUri, proposalS256);
    public static R3EnforcementDecision Rejected(string error) => new(R3EnforcementDecisionKind.Rejected, Error: error);

    public IResult ToResult()
    {
        return Kind switch
        {
            R3EnforcementDecisionKind.Granted => Results.Ok(),
            R3EnforcementDecisionKind.Conditional => Results.Json(
                new { error = "r3_approval_required", r3_uri = ProposalUri, r3_s256 = ProposalS256 },
                statusCode: StatusCodes.Status401Unauthorized),
            _ => Results.Json(new { error = Error ?? "r3_denied" }, statusCode: StatusCodes.Status403Forbidden),
        };
    }
}

public enum R3EnforcementDecisionKind
{
    Granted,
    Conditional,
    Rejected,
}

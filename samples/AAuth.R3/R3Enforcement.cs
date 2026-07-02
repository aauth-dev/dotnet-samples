using System.Text.Json.Nodes;
using AAuth.Headers;
using AAuth.R3.Model;
using AAuth.Tokens;
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

        if (approvedProposalS256 is not null)
        {
            return EvaluateApprovedProposalRetry(
                claims,
                tool,
                parameters is null ? null : R3PresentedParameters.FromJsonParameters(parameters),
                approvedProposalS256);
        }

        if (claims.Granted.ContainsTool(tool))
        {
            return R3EnforcementDecision.Granted();
        }

        if (!claims.Conditional?.ContainsTool(tool) ?? true)
        {
            return R3EnforcementDecision.Rejected("operation_not_granted");
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

    public R3EnforcementDecision Evaluate(
        R3ClaimReader.AuthTokenClaims claims,
        string tool,
        R3PresentedParameters presentedParameters,
        string approvedProposalS256)
    {
        ArgumentNullException.ThrowIfNull(presentedParameters);
        ArgumentException.ThrowIfNullOrEmpty(approvedProposalS256);
        return EvaluateApprovedProposalRetry(claims, tool, presentedParameters, approvedProposalS256);
    }

    public R3EnforcementDecision Evaluate(JsonObject verifiedAuthTokenPayload, string tool, IReadOnlyDictionary<string, R3Parameter>? parameters = null, string? approvedProposalS256 = null) =>
        Evaluate(R3ClaimReader.ReadAuthToken(verifiedAuthTokenPayload), tool, parameters, approvedProposalS256: approvedProposalS256);

    private R3EnforcementDecision EvaluateApprovedProposalRetry(
        R3ClaimReader.AuthTokenClaims claims,
        string tool,
        R3PresentedParameters? presentedParameters,
        string approvedProposalS256)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentException.ThrowIfNullOrEmpty(tool);

        if (!claims.Granted.ContainsTool(tool))
        {
            return R3EnforcementDecision.Rejected("operation_not_granted");
        }

        if (!string.Equals(claims.S256, approvedProposalS256, StringComparison.Ordinal))
        {
            return R3EnforcementDecision.Rejected("proposal_token_mismatch");
        }

        if (presentedParameters is null || !_proposalStore.TryGet(approvedProposalS256, out var stored))
        {
            return R3EnforcementDecision.Rejected("unknown_proposal");
        }

        R3ProposalDocument expected;
        try
        {
            expected = R3ProposalDocument.FromUtf8Bytes(stored);
        }
        catch (InvalidOperationException)
        {
            return R3EnforcementDecision.Rejected("invalid_proposal");
        }

        if (!expected.Operations.Any(op => string.Equals(op.Tool, tool, StringComparison.Ordinal)))
        {
            return R3EnforcementDecision.Rejected("proposal_tool_mismatch");
        }

        return MatchesExpectedParameters(expected.Parameters, presentedParameters)
            ? R3EnforcementDecision.Granted()
            : R3EnforcementDecision.Rejected("proposal_digest_mismatch");
    }

    private static bool MatchesExpectedParameters(
        IReadOnlyDictionary<string, R3Parameter> expectedParameters,
        R3PresentedParameters presentedParameters)
    {
        var expectedNames = expectedParameters.Keys.ToHashSet(StringComparer.Ordinal);
        if (presentedParameters.JsonParameters.Keys.Any(name => !expectedNames.Contains(name))
            || presentedParameters.DigestParameterNames.Any(name => !expectedNames.Contains(name)))
        {
            return false;
        }

        foreach (var (name, expected) in expectedParameters)
        {
            if (expected.TryGetDigestS256(out var expectedS256))
            {
                if (!presentedParameters.TryGetDigestParameterBytes(name, out var presentedBytes)
                    || !string.Equals(R3Hash.ComputeS256(presentedBytes.Span), expectedS256, StringComparison.Ordinal))
                {
                    return false;
                }
                continue;
            }

            if (!presentedParameters.JsonParameters.TryGetValue(name, out var presented)
                || !JsonNode.DeepEquals(expected.Json, presented.Json))
            {
                return false;
            }
        }

        return true;
    }
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
            R3EnforcementDecisionKind.Conditional => throw new InvalidOperationException(
                "Conditional R3 decisions require an AAuth-Requirement challenge; call the ToResult overload that receives HttpContext and R3Challenge."),
            _ => Results.Json(new { error = Error ?? "r3_denied" }, statusCode: StatusCodes.Status403Forbidden),
        };
    }

    public IResult ToResult(HttpContext context, R3Challenge challenge, string agent, string agentJkt, string? scope = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(challenge);

        if (Kind != R3EnforcementDecisionKind.Conditional)
        {
            return ToResult();
        }
        var proposal = RequireConditionalProposal();
        var resourceToken = challenge.BuildResourceToken(agent, agentJkt, proposal.Uri, proposal.S256, scope);
        return ToConditionalChallengeResult(context, resourceToken);
    }

    public IResult ToResult(HttpContext context, R3Challenge challenge, TokenVerifier.VerifiedToken verifiedAuthToken, string? scope = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(verifiedAuthToken);

        if (Kind != R3EnforcementDecisionKind.Conditional)
        {
            return ToResult();
        }

        var proposal = RequireConditionalProposal();
        var resourceToken = challenge.BuildResourceToken(verifiedAuthToken, proposal.Uri, proposal.S256, scope);
        return ToConditionalChallengeResult(context, resourceToken);
    }

    private IResult ToConditionalChallengeResult(HttpContext context, string resourceToken)
    {
        var proposal = RequireConditionalProposal();

        context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(resourceToken);
        return Results.Json(
            new { error = "r3_approval_required", r3_uri = proposal.Uri, r3_s256 = proposal.S256 },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    private (string Uri, string S256) RequireConditionalProposal()
    {
        if (string.IsNullOrWhiteSpace(ProposalUri) || string.IsNullOrWhiteSpace(ProposalS256))
        {
            throw new InvalidOperationException("Conditional R3 decisions require proposal uri and s256.");
        }

        return (ProposalUri, ProposalS256);
    }
}

public enum R3EnforcementDecisionKind
{
    Granted,
    Conditional,
    Rejected,
}

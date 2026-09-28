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
    private readonly R3VocabularySchemas _schemas;

    public R3Enforcement(R3ProposalStore proposalStore, Uri resourceBaseUri, string proposalPathPrefix = "/r3/proposals", R3VocabularySchemas? schemas = null)
    {
        _proposalStore = proposalStore;
        _resourceBaseUri = resourceBaseUri;
        _proposalPathPrefix = proposalPathPrefix;
        _schemas = schemas ?? R3VocabularySchemas.Standard;
    }

    public R3EnforcementDecision Evaluate(
        R3ClaimReader.AuthTokenClaims claims,
        R3OperationIdentity operation,
        IReadOnlyDictionary<string, R3Parameter>? parameters = null,
        Func<R3OperationIdentity, IReadOnlyDictionary<string, R3Parameter>, R3Display?>? displayFactory = null,
        string? approvedProposalS256 = null,
        string? expectedAccount = null)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(operation);
        _schemas.Validate(operation.Vocabulary, operation.Operation);
        claims.Granted.Validate(allowEmpty: true, _schemas);
        claims.Conditional?.Validate(allowEmpty: true, _schemas);
        if (!AccountBinding.Matches(expectedAccount, claims.Account))
            return R3EnforcementDecision.Rejected("account_mismatch");

        if (approvedProposalS256 is not null)
        {
            return EvaluateApprovedProposalRetry(
                claims,
                operation,
                parameters is null ? null : R3PresentedParameters.FromJsonParameters(parameters),
                approvedProposalS256);
        }

        if (claims.Granted.Contains(operation))
        {
            return R3EnforcementDecision.Granted();
        }

        var conditional = claims.Conditional;
        if (conditional is null || !conditional.Contains(operation))
        {
            return R3EnforcementDecision.Rejected("operation_not_granted");
        }

        if (parameters is null)
        {
            return R3EnforcementDecision.Rejected("parameters_required");
        }

        var proposal = new R3ProposalDocument
        {
            Version = "v02",
            Vocabulary = conditional.Vocabulary,
            Operations = [operation.Operation],
            Parameters = parameters,
            Display = displayFactory?.Invoke(operation, parameters),
            Account = claims.Account,
        };
        var storedProposal = _proposalStore.Add(proposal, _resourceBaseUri, _proposalPathPrefix, _schemas);
        return R3EnforcementDecision.Conditional(storedProposal.Uri, storedProposal.S256) with { Account = claims.Account };
    }

    public R3EnforcementDecision Evaluate(
        R3ClaimReader.AuthTokenClaims claims,
        R3OperationIdentity operation,
        R3PresentedParameters presentedParameters,
        string approvedProposalS256,
        string? expectedAccount = null)
    {
        ArgumentNullException.ThrowIfNull(presentedParameters);
        ArgumentException.ThrowIfNullOrEmpty(approvedProposalS256);
        if (!AccountBinding.Matches(expectedAccount, claims.Account))
            return R3EnforcementDecision.Rejected("account_mismatch");
        return EvaluateApprovedProposalRetry(claims, operation, presentedParameters, approvedProposalS256);
    }

    public R3EnforcementDecision Evaluate(JsonObject verifiedAuthTokenPayload, R3OperationIdentity operation, IReadOnlyDictionary<string, R3Parameter>? parameters = null, string? approvedProposalS256 = null, string? expectedAccount = null) =>
        Evaluate(R3ClaimReader.ReadAuthToken(verifiedAuthTokenPayload, _schemas), operation, parameters, approvedProposalS256: approvedProposalS256, expectedAccount: expectedAccount);

    private R3EnforcementDecision EvaluateApprovedProposalRetry(
        R3ClaimReader.AuthTokenClaims claims,
        R3OperationIdentity operation,
        R3PresentedParameters? presentedParameters,
        string approvedProposalS256)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(operation);
        _schemas.Validate(operation.Vocabulary, operation.Operation);
        claims.Granted.Validate(allowEmpty: true, _schemas);

        if (!claims.Granted.Contains(operation))
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
            R3Hash.Verify(stored, approvedProposalS256);
            expected = R3ProposalDocument.FromUtf8Bytes(stored, schemas: _schemas);
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.Text.Json.JsonException or R3HashMismatchException)
        {
            return R3EnforcementDecision.Rejected("invalid_proposal");
        }

        if (!AccountBinding.Matches(expected.Account, claims.Account))
            return R3EnforcementDecision.Rejected("proposal_account_mismatch");

        if (!expected.Operations.Any(op => operation.Matches(expected.Vocabulary, op)))
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
    public string? Account { get; init; }
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
            _ => AAuth.Server.AAuthProblemDetails.Create(Error ?? "r3_denied", statusCode: StatusCodes.Status403Forbidden),
        };
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
        return AAuth.Server.AAuthProblemDetails.Create("r3_approval_required",
            statusCode: StatusCodes.Status401Unauthorized,
            extensions: new Dictionary<string, object?>
            {
                ["r3_uri"] = proposal.Uri,
                ["r3_s256"] = proposal.S256,
            });
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

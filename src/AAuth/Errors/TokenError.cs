namespace AAuth.Errors;

/// <summary>
/// Error codes from the AAuth token endpoint per §Token Endpoint Error Codes.
/// Token-specific codes exist only for tokens carried as request parameters,
/// named <c>&lt;invalid|expired|revoked&gt;_&lt;parameter&gt;_token</c>.
/// </summary>
public enum TokenErrorCode
{
    /// <summary>Malformed JSON, missing required fields.</summary>
    InvalidRequest,

    /// <summary>
    /// Draft-10 agent-token parameter failure. Draft-11 answers a failing agent
    /// token with <c>Signature-Error</c>; the exchange cutover removes this code.
    /// </summary>
    InvalidAgentToken,

    /// <summary>Draft-10 agent-token parameter expiry; removed with <see cref="InvalidAgentToken"/>.</summary>
    ExpiredAgentToken,

    /// <summary>Resource token malformed or signature verification failed.</summary>
    InvalidResourceToken,

    /// <summary>Resource token has expired.</summary>
    ExpiredResourceToken,

    /// <summary>The issuing resource withdrew the resource token. Terminal for that token.</summary>
    RevokedResourceToken,

    /// <summary>Presented token malformed, unverifiable, or neither a person nor an auth token.</summary>
    InvalidPresentedToken,

    /// <summary>Presented token expired; obtain a fresh person token, then a fresh resource token.</summary>
    ExpiredPresentedToken,

    /// <summary>Presented token revoked by its issuer; obtain a fresh person token, then a fresh resource token.</summary>
    RevokedPresentedToken,

    /// <summary>Upstream token malformed, unverifiable, or not addressed to the requesting intermediary.</summary>
    InvalidUpstreamToken,

    /// <summary>Upstream token expired; the calling agent re-authorizes at the intermediary.</summary>
    ExpiredUpstreamToken,

    /// <summary>Upstream token, or the calling agent's token or person binding, was revoked. Terminal.</summary>
    RevokedUpstreamToken,

    /// <summary>Sub-agent token malformed, unverifiable, or not issued under the signing agent.</summary>
    InvalidSubagentToken,

    /// <summary>Sub-agent token expired; the parent obtains a fresh one.</summary>
    ExpiredSubagentToken,

    /// <summary>Sub-agent token revoked by its agent provider. Terminal for that token.</summary>
    RevokedSubagentToken,

    /// <summary>A parameter token's <c>iat</c> is further ahead than the validity window. Do not refresh.</summary>
    ClockSkew,

    /// <summary>
    /// The PS has no channel to reach the user and the agent did not declare
    /// the <c>interaction</c> capability. Terminal (HTTP 403).
    /// </summary>
    UserUnreachable,

    /// <summary>
    /// PS only (HTTP 502): no verifiable auth token could be obtained from the
    /// access server. Retry with a fresh resource token after a backoff.
    /// </summary>
    AsUnreachable,

    /// <summary>
    /// The request carried a <c>mission_s256</c> referencing a mission that is
    /// no longer active. Terminal (HTTP 403) per §Mission Status Errors.
    /// </summary>
    MissionTerminated,

    /// <summary>Internal error.</summary>
    ServerError,
}

/// <summary>
/// Represents a structured error response from an AAuth token endpoint.
/// </summary>
/// <param name="Error">The error code.</param>
/// <param name="Detail">Optional human-readable description.</param>
public sealed record TokenErrorResponse(TokenErrorCode Error, string? Detail = null)
{
    private static readonly IReadOnlyDictionary<TokenErrorCode, string> WireCodes = new Dictionary<TokenErrorCode, string>
    {
        [TokenErrorCode.InvalidRequest] = "invalid_request",
        [TokenErrorCode.InvalidAgentToken] = "invalid_agent_token",
        [TokenErrorCode.ExpiredAgentToken] = "expired_agent_token",
        [TokenErrorCode.InvalidResourceToken] = "invalid_resource_token",
        [TokenErrorCode.ExpiredResourceToken] = "expired_resource_token",
        [TokenErrorCode.RevokedResourceToken] = "revoked_resource_token",
        [TokenErrorCode.InvalidPresentedToken] = "invalid_presented_token",
        [TokenErrorCode.ExpiredPresentedToken] = "expired_presented_token",
        [TokenErrorCode.RevokedPresentedToken] = "revoked_presented_token",
        [TokenErrorCode.InvalidUpstreamToken] = "invalid_upstream_token",
        [TokenErrorCode.ExpiredUpstreamToken] = "expired_upstream_token",
        [TokenErrorCode.RevokedUpstreamToken] = "revoked_upstream_token",
        [TokenErrorCode.InvalidSubagentToken] = "invalid_subagent_token",
        [TokenErrorCode.ExpiredSubagentToken] = "expired_subagent_token",
        [TokenErrorCode.RevokedSubagentToken] = "revoked_subagent_token",
        [TokenErrorCode.ClockSkew] = "clock_skew",
        [TokenErrorCode.UserUnreachable] = "user_unreachable",
        [TokenErrorCode.AsUnreachable] = "as_unreachable",
        [TokenErrorCode.MissionTerminated] = "mission_terminated",
        [TokenErrorCode.ServerError] = "server_error",
    };

    private static readonly IReadOnlyDictionary<string, TokenErrorCode> Codes =
        WireCodes.ToDictionary(pair => pair.Value, pair => pair.Key, StringComparer.Ordinal);

    /// <summary>The wire-format error code string.</summary>
    public string ErrorCode => WireCodes.TryGetValue(Error, out var code) ? code : "server_error";

    /// <summary>Try to parse a wire-format error code string.</summary>
    public static bool TryParseCode(string? code, out TokenErrorCode result)
    {
        result = default;
        return code is not null && Codes.TryGetValue(code, out result);
    }
}

namespace AAuth.Errors;

/// <summary>
/// Error codes from the AAuth token endpoint per §Token Endpoint Error Codes.
/// </summary>
public enum TokenErrorCode
{
    /// <summary>Malformed JSON, missing required fields.</summary>
    InvalidRequest,

    /// <summary>Agent token malformed or signature verification failed.</summary>
    InvalidAgentToken,

    /// <summary>Agent token has expired.</summary>
    ExpiredAgentToken,

    /// <summary>Resource token malformed or signature verification failed.</summary>
    InvalidResourceToken,

    /// <summary>Resource token has expired.</summary>
    ExpiredResourceToken,

    /// <summary>User interaction is needed but not available.</summary>
    InteractionRequired,

    /// <summary>
    /// The PS has no channel to reach the user and the agent did not declare
    /// the <c>interaction</c> capability. Terminal (HTTP 400) — distinct from
    /// <see cref="InteractionRequired"/>, which is a non-terminal 202 carrying
    /// an interaction URL. Per draft-02 §Token Endpoint Error Codes.
    /// </summary>
    UserUnreachable,

    /// <summary>Internal error.</summary>
    ServerError,
}

/// <summary>
/// Represents a structured error response from an AAuth token endpoint.
/// </summary>
/// <param name="Error">The error code.</param>
/// <param name="ErrorDescription">Optional human-readable description.</param>
public sealed record TokenErrorResponse(TokenErrorCode Error, string? ErrorDescription = null)
{
    /// <summary>The wire-format error code string.</summary>
    public string ErrorCode => Error switch
    {
        TokenErrorCode.InvalidRequest => "invalid_request",
        TokenErrorCode.InvalidAgentToken => "invalid_agent_token",
        TokenErrorCode.ExpiredAgentToken => "expired_agent_token",
        TokenErrorCode.InvalidResourceToken => "invalid_resource_token",
        TokenErrorCode.ExpiredResourceToken => "expired_resource_token",
        TokenErrorCode.InteractionRequired => "interaction_required",
        TokenErrorCode.UserUnreachable => "user_unreachable",
        TokenErrorCode.ServerError => "server_error",
        _ => "server_error",
    };

    /// <summary>Try to parse a wire-format error code string.</summary>
    public static bool TryParseCode(string? code, out TokenErrorCode result)
    {
        result = code switch
        {
            "invalid_request" => TokenErrorCode.InvalidRequest,
            "invalid_agent_token" => TokenErrorCode.InvalidAgentToken,
            "expired_agent_token" => TokenErrorCode.ExpiredAgentToken,
            "invalid_resource_token" => TokenErrorCode.InvalidResourceToken,
            "expired_resource_token" => TokenErrorCode.ExpiredResourceToken,
            "interaction_required" => TokenErrorCode.InteractionRequired,
            "user_unreachable" => TokenErrorCode.UserUnreachable,
            "server_error" => TokenErrorCode.ServerError,
            _ => default,
        };
        return code is "invalid_request" or "invalid_agent_token" or "expired_agent_token"
            or "invalid_resource_token" or "expired_resource_token"
            or "interaction_required" or "user_unreachable" or "server_error";
    }
}

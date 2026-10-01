namespace AAuth.Errors;

/// <summary>Revocation endpoint error codes per §Token Revocation. There is no "not found".</summary>
public enum RevocationErrorCode
{
    /// <summary>Malformed body, or missing <c>jti</c> or <c>exp</c>. HTTP 400.</summary>
    InvalidRequest,

    /// <summary>The recipient does not accept revocations from this issuer. HTTP 403.</summary>
    UnsupportedIss,

    /// <summary>Too many revocations from this caller for now. HTTP 429 with a REQUIRED <c>Retry-After</c>.</summary>
    RateLimited,

    /// <summary>Internal error. HTTP 500.</summary>
    ServerError,
}

/// <summary>Why a downstream revocation in a cascade did not succeed, as reported in a <c>downstream</c> entry.</summary>
public enum RevocationDownstreamError
{
    /// <summary>The party was unreachable or answered <c>5xx</c>. Revocation is idempotent; retry later.</summary>
    RevocationUnavailable,

    /// <summary>The party publishes no <c>revocation_endpoint</c> or answered <c>unsupported_iss</c>; it honors tokens until <c>exp</c>.</summary>
    RevocationUnsupported,
}

/// <summary>Wire mapping for <see cref="RevocationErrorCode"/> and <see cref="RevocationDownstreamError"/>.</summary>
public static class RevocationError
{
    /// <summary>Wire code for a revocation endpoint error.</summary>
    public static string ToWireCode(RevocationErrorCode code) => code switch
    {
        RevocationErrorCode.InvalidRequest => "invalid_request",
        RevocationErrorCode.UnsupportedIss => "unsupported_iss",
        RevocationErrorCode.RateLimited => "rate_limited",
        _ => "server_error",
    };

    /// <summary>HTTP status for a revocation endpoint error.</summary>
    public static int StatusCode(RevocationErrorCode code) => code switch
    {
        RevocationErrorCode.InvalidRequest => 400,
        RevocationErrorCode.UnsupportedIss => 403,
        RevocationErrorCode.RateLimited => 429,
        _ => 500,
    };

    /// <summary>Try to parse a revocation endpoint error code.</summary>
    public static bool TryParseCode(string? code, out RevocationErrorCode result)
    {
        result = code switch
        {
            "invalid_request" => RevocationErrorCode.InvalidRequest,
            "unsupported_iss" => RevocationErrorCode.UnsupportedIss,
            "rate_limited" => RevocationErrorCode.RateLimited,
            _ => RevocationErrorCode.ServerError,
        };
        return code is "invalid_request" or "unsupported_iss" or "rate_limited" or "server_error";
    }

    /// <summary>Wire value of a downstream entry's <c>error</c> member.</summary>
    public static string ToWireCode(RevocationDownstreamError error) => error switch
    {
        RevocationDownstreamError.RevocationUnavailable => "revocation_unavailable",
        _ => "revocation_unsupported",
    };

    /// <summary>Try to parse a downstream entry's <c>error</c> member.</summary>
    public static bool TryParseDownstream(string? code, out RevocationDownstreamError result)
    {
        result = code == "revocation_unavailable" ? RevocationDownstreamError.RevocationUnavailable : RevocationDownstreamError.RevocationUnsupported;
        return code is "revocation_unavailable" or "revocation_unsupported";
    }
}

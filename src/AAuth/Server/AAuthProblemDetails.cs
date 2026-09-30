using Microsoft.AspNetCore.Http;
using AAuth.Errors;

namespace AAuth.Server;

public static class AAuthProblemDetails
{
    public const string ContentType = "application/problem+json";

    public static IResult TokenFailure(Tokens.TokenVerificationException exception,
        Tokens.TokenCredential credential = Tokens.TokenCredential.Agent)
    {
        var expired = exception.Code == Errors.SignatureErrorCode.ExpiredJwt;
        var skew = exception.Code == Errors.SignatureErrorCode.ClockSkew;
        var revoked = exception.Code == Errors.SignatureErrorCode.RevokedJwt;
        var parameter = (exception.Credential ?? credential) switch
        {
            Tokens.TokenCredential.Resource => "resource",
            Tokens.TokenCredential.Upstream => "upstream",
            Tokens.TokenCredential.Subagent => "subagent",
            Tokens.TokenCredential.Presented => "presented",
            _ => "agent",
        };
        var error = skew ? "clock_skew" : $"{(expired ? "expired" : revoked ? "revoked" : "invalid")}_{parameter}_token";
        return Create(error, exception.Message);
    }

    /// <summary>
    /// A source token failed registration on a first request (#token-revocation): a
    /// parameter token is 400 <c>revoked_&lt;parameter&gt;_token</c>; the
    /// <c>Signature-Key</c> token is 401 <c>Signature-Error: error=revoked_jwt</c>.
    /// </summary>
    public static IResult SourceRevoked(Tokens.TokenVerificationException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (exception.Credential is { } credential) return TokenFailure(exception, credential);
        return new SignatureErrorResult(Errors.SignatureError.Format(Errors.SignatureErrorCode.RevokedJwt));
    }

    /// <summary>
    /// A source token of a fresh (non-pending) request expired before issuance: a
    /// parameter token is 400 <c>expired_&lt;parameter&gt;_token</c>; the
    /// <c>Signature-Key</c> token is 401 <c>Signature-Error: error=expired_jwt</c>.
    /// Returns <paramref name="otherwise"/> when no source has expired.
    /// </summary>
    public static IResult SourceExpired(IEnumerable<TokenRegistration> sources, DateTimeOffset now, IResult? otherwise = null)
    {
        ArgumentNullException.ThrowIfNull(sources);
        foreach (var source in sources.Where(source => source.ExpiresAt.ToUnixTimeSeconds() <= now.ToUnixTimeSeconds())
            .OrderBy(source => source.Credential is null ? 0 : 1))
        {
            return source.Credential is { } credential
                ? TokenFailure(new Tokens.TokenVerificationException(Errors.SignatureErrorCode.ExpiredJwt, "The token has expired."), credential)
                : new SignatureErrorResult(Errors.SignatureError.Format(Errors.SignatureErrorCode.ExpiredJwt));
        }
        return otherwise ?? new SignatureErrorResult(Errors.SignatureError.Format(Errors.SignatureErrorCode.ExpiredJwt));
    }

    internal static IResult SignatureFailure(SignatureErrorCode code,
        IEnumerable<string>? requiredInput = null,
        IEnumerable<string>? acceptedSchemes = null,
        IEnumerable<string>? acceptedAlgorithms = null,
        int statusCode = StatusCodes.Status401Unauthorized)
    {
        return new SignatureErrorResult(SignatureError.Format(code, requiredInput: requiredInput?.ToArray()),
            acceptedSchemes, acceptedAlgorithms, statusCode);
    }

    internal static Task WriteSignatureFailureAsync(HttpContext context, SignatureErrorCode code,
        IEnumerable<string>? requiredInput = null,
        IEnumerable<string>? acceptedSchemes = null,
        IEnumerable<string>? acceptedAlgorithms = null,
        int statusCode = StatusCodes.Status401Unauthorized)
        => SignatureFailure(code, requiredInput, acceptedSchemes, acceptedAlgorithms, statusCode).ExecuteAsync(context);

    internal static IResult MissingCoverage(IEnumerable<string> required) =>
        SignatureFailure(SignatureErrorCode.InvalidInput,
            requiredInput: HttpSig.AAuthSigningHandler.CoveredComponents.Concat(required).Distinct().ToArray());

    private static readonly string[] BodyComponents = ["content-type", "content-digest"];

    // §Covered Components: a body-bearing request to a PS or AS endpoint MUST
    // cover content-type and content-digest. Returns the 401 invalid_input
    // response when the verified signature does not, else null.
    internal static IResult? MissingBodyCoverage(HttpContext context) =>
        context.Features.Get<Verification.AAuthVerificationResult>() is { } verified
            && !verified.CoveredComponents.IsSupersetOf(BodyComponents)
            ? MissingCoverage(BodyComponents) : null;

    private sealed class SignatureErrorResult(string header, IEnumerable<string>? acceptedSchemes = null,
        IEnumerable<string>? acceptedAlgorithms = null, int statusCode = StatusCodes.Status401Unauthorized) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.StatusCode = statusCode;
            httpContext.Response.Headers[Errors.SignatureError.HeaderName] = header;
            if (acceptedSchemes is not null)
                httpContext.Response.Headers["Accept-Signature-Scheme"] = string.Join(", ", acceptedSchemes);
            if (acceptedAlgorithms is not null)
                httpContext.Response.Headers["Accept-Signature-Alg"] = string.Join(", ", acceptedAlgorithms);
            return Task.CompletedTask;
        }
    }

    public static IResult Create(
        string error,
        string? detail = null,
        int statusCode = StatusCodes.Status400BadRequest,
        IDictionary<string, object?>? extensions = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(error);
        if (statusCode is < 400 or > 599)
            throw new ArgumentOutOfRangeException(nameof(statusCode));

        var body = extensions is null
            ? new Dictionary<string, object?>()
            : new Dictionary<string, object?>(extensions);
        body["error"] = error;
        body.Remove("detail");
        if (detail is not null)
            body["detail"] = detail;

        return Results.Json(body, statusCode: statusCode, contentType: ContentType);
    }

    public static Task WriteAsync(
        HttpContext context,
        string error,
        string? detail = null,
        int statusCode = StatusCodes.Status400BadRequest,
        IDictionary<string, object?>? extensions = null)
        => Create(error, detail, statusCode, extensions).ExecuteAsync(context);
}
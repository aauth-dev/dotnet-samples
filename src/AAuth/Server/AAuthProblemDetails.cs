using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

public static class AAuthProblemDetails
{
    public const string ContentType = "application/problem+json";

    public static IResult TokenFailure(Tokens.TokenVerificationException exception,
        Tokens.TokenCredential credential = Tokens.TokenCredential.Agent)
    {
        var expired = exception.Code == Errors.SignatureErrorCode.ExpiredJwt;
        var error = (exception.Credential ?? credential) switch
        {
            Tokens.TokenCredential.Resource => expired ? "expired_resource_token" : "invalid_resource_token",
            Tokens.TokenCredential.Upstream => "invalid_upstream_token",
            _ => expired ? "expired_agent_token" : "invalid_agent_token",
        };
        return Create(error, exception.Message);
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
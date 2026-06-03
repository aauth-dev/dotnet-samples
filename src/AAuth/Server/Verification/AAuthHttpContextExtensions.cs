using AAuth.Headers;
using AAuth.HttpSig;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server.Verification;

/// <summary>
/// Extension methods on <see cref="HttpContext"/> for convenient access to
/// AAuth verification results and protocol response helpers.
/// </summary>
public static class AAuthHttpContextExtensions
{
    // -----------------------------------------------------------------------
    // Request-side: reading verification results
    // -----------------------------------------------------------------------

    /// <summary>
    /// Gets the <see cref="AAuthVerificationResult"/> from <c>HttpContext.Features</c>.
    /// Returns null if verification middleware has not run.
    /// </summary>
    public static AAuthVerificationResult? GetAAuthVerification(this HttpContext context)
        => context.Features.Get<AAuthVerificationResult>();

    /// <summary>
    /// Gets the <see cref="SignatureKeyParser.ParsedSignatureKeyInfo"/> from <c>HttpContext.Items</c>.
    /// Returns null if verification middleware has not run.
    /// </summary>
    public static SignatureKeyParser.ParsedSignatureKeyInfo? GetAAuthParsedKey(this HttpContext context)
        => context.Items.TryGetValue(AAuthVerificationMiddleware.ParsedInfoItemKey, out var obj)
            ? obj as SignatureKeyParser.ParsedSignatureKeyInfo
            : null;

    /// <summary>
    /// Gets the <see cref="VerificationResult"/> from <c>HttpContext.Items</c>.
    /// Prefer <see cref="GetAAuthVerification"/> which returns the richer typed result.
    /// </summary>
    public static VerificationResult? GetAAuthResult(this HttpContext context)
        => context.Items.TryGetValue(AAuthVerificationMiddleware.ContextItemKey, out var obj)
            ? obj as VerificationResult
            : null;

    /// <summary>
    /// Gets the token type from the verified request as an <see cref="AAuthTokenType"/>.
    /// Returns <see cref="AAuthTokenType.Unknown"/> if verification middleware has not run
    /// or the token type is unrecognized.
    /// </summary>
    public static AAuthTokenType GetAAuthTokenType(this HttpContext context)
        => context.GetAAuthVerification()?.TokenType ?? AAuthTokenType.Unknown;

    // -----------------------------------------------------------------------
    // Response-side: protocol challenge and error helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Issues an AAuth challenge by setting the <c>AAuth-Requirement</c> header with
    /// an <c>auth-token</c> requirement and returning 401 Unauthorized.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="resourceToken">The signed resource token JWT string.</param>
    /// <returns>An <see cref="IResult"/> that writes the 401 response.</returns>
    public static IResult ChallengeAAuth(this HttpContext context, string resourceToken)
    {
        context.Response.Headers[AAuthConstants.Headers.AAuthRequirement] =
            AAuthRequirementHeader.FormatAuthToken(resourceToken);
        return Results.Json(
            new { error = "auth_token_required" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    /// <summary>
    /// Sets the <c>AAuth-Error</c> response header with the given message.
    /// Does not change the status code — call this before returning an error result.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="message">A human-readable error message.</param>
    public static void SetAAuthError(this HttpContext context, string message)
    {
        context.Response.Headers[AAuthConstants.Headers.AAuthError] = message;
    }
}

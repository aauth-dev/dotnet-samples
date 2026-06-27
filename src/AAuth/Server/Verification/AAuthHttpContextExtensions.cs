using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using Microsoft.AspNetCore.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server.Verification;

/// <summary>
/// Extension methods on <see cref="HttpContext"/> for convenient access to
/// AAuth verification results and protocol response helpers.
/// </summary>
public static class AAuthHttpContextExtensions
{
    /// <summary>
    /// <c>HttpContext.Items</c> key under which a resolved resource-managed
    /// <see cref="OpaqueTokenInfo"/> is cached by
    /// <see cref="ResolveAAuthAccessAsync"/>.
    /// </summary>
    public const string AAuthAccessInfoItemKey = "AAuth.OpaqueTokenInfo";

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

    // -----------------------------------------------------------------------
    // Resource-managed (two-party) AAuth-Access opaque-token helpers
    // (§AAuth-Access Response Header, §Resource-Managed Authorization)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Resolve an inbound resource-managed opaque token: read the
    /// <c>Authorization: AAuth &lt;token68&gt;</c> credential, validate the
    /// <c>token68</c> grammar, and look it up in <paramref name="store"/>.
    /// Returns the <see cref="OpaqueTokenInfo"/> on success, or
    /// <see langword="null"/> when no (valid) token is present or it is
    /// unknown/expired. The result is cached on <c>HttpContext.Items</c> for
    /// <see cref="TryGetAAuthAccess"/>.
    /// </summary>
    /// <remarks>
    /// The signature binding (the MUST that <c>authorization</c> is a covered
    /// component) is enforced upstream by <see cref="AAuthVerifier"/> during
    /// <see cref="AAuthVerificationMiddleware"/>. This method therefore requires
    /// that verification has run — if it has not, the token is not honored
    /// (returns <see langword="null"/>), so an opaque token can never be accepted
    /// without a verified AAuth signature. More than one <c>Authorization</c>
    /// header value is rejected (§AAuth-Access: "more than one credential").
    /// </remarks>
    public static async Task<OpaqueTokenInfo?> ResolveAAuthAccessAsync(
        this HttpContext context,
        IOpaqueTokenStore store,
        CancellationToken cancellationToken = default)
    {
        System.ArgumentNullException.ThrowIfNull(store);

        // Require a verified AAuth signature: the binding of the opaque token to
        // the request is only meaningful when the signature (covering
        // `authorization`) verified.
        if (context.GetAAuthVerification() is null)
        {
            return null;
        }

        var authorization = context.Request.Headers.Authorization;
        // Reject "more than one credential" (more than one header value).
        if (authorization.Count != 1)
        {
            return null;
        }

        if (!AAuthAccessHeader.TryParseAuthorization(authorization.ToString(), out var token68))
        {
            return null;
        }

        var info = await store.ValidateAsync(token68, cancellationToken).ConfigureAwait(false);
        if (info is not null)
        {
            context.Items[AAuthAccessInfoItemKey] = info;
        }

        return info;
    }

    /// <summary>
    /// Get a resource-managed <see cref="OpaqueTokenInfo"/> previously resolved by
    /// <see cref="ResolveAAuthAccessAsync"/> on this request, if any.
    /// </summary>
    public static bool TryGetAAuthAccess(this HttpContext context, out OpaqueTokenInfo? info)
    {
        if (context.Items.TryGetValue(AAuthAccessInfoItemKey, out var obj) && obj is OpaqueTokenInfo resolved)
        {
            info = resolved;
            return true;
        }

        info = null;
        return false;
    }

    /// <summary>
    /// Issue a resource-managed opaque access token: mint it in
    /// <paramref name="store"/> and emit it on the response via the
    /// <c>AAuth-Access</c> header (§AAuth-Access Response Header). Call again on a
    /// later response to roll the token (rolling refresh, §AAuth-Access). Returns
    /// the issued <c>token68</c>.
    /// </summary>
    public static async Task<string> IssueAAuthAccessAsync(
        this HttpContext context,
        IOpaqueTokenStore store,
        OpaqueTokenInfo info,
        CancellationToken cancellationToken = default)
    {
        System.ArgumentNullException.ThrowIfNull(store);
        System.ArgumentNullException.ThrowIfNull(info);

        var token = await store.IssueAsync(info, cancellationToken).ConfigureAwait(false);
        // Validate the token68 grammar before emitting it (defensive: a custom
        // store could return an unsafe value).
        context.Response.Headers[AAuthConstants.Headers.AAuthAccess] = AAuthAccessHeader.FormatAccess(token);
        return token;
    }

    /// <summary>
    /// Issue a <c>202 Accepted</c> resource-managed interaction requirement
    /// (§Resource-Managed Authorization): set
    /// <c>AAuth-Requirement: requirement=interaction; url=…; code=…</c> and the
    /// <c>Location</c> the agent polls until authorization completes.
    /// </summary>
    public static IResult InteractionRequiredAAuth(
        this HttpContext context,
        string interactionUrl,
        string code,
        string pendingLocation)
    {
        context.Response.Headers[AAuthConstants.Headers.AAuthRequirement] =
            Interaction.Format(interactionUrl, code);
        context.Response.Headers.Location = pendingLocation;
        context.Response.Headers.CacheControl = "no-store";
        return Results.Json(
            new { status = "pending" },
            statusCode: StatusCodes.Status202Accepted);
    }
}

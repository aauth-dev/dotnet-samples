using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Identifiers;
using AAuth.Server.CallChaining;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server.Verification;

/// <summary>
/// ASP.NET Core middleware that verifies AAuth HTTP signatures (RFC 9421 PoP)
/// and JWT issuer signatures in a single pass.
/// </summary>
/// <remarks>
/// <list type="number">
/// <item>Pull Signature, Signature-Input, Signature-Key headers.</item>
/// <item>Validate selected labels, required input and signature timestamps.</item>
/// <item>Resolve the key after verifying any JWT assertion and its expected type.</item>
/// <item>Verify the RFC 9421 signature and any covered body digest.</item>
/// <item>Apply issuer policy and auth-token audience, confirmation and actor checks.</item>
/// <item>Store <see cref="VerificationResult"/> in HttpContext.Items.</item>
/// </list>
/// </remarks>
public sealed class AAuthVerificationMiddleware
{
    /// <summary><see cref="HttpContext.Items"/> key for the <see cref="VerificationResult"/>.</summary>
    public const string ContextItemKey = "AAuth.VerificationResult";

    /// <summary><see cref="HttpContext.Items"/> key for the parsed <see cref="SignatureKeyParser.ParsedSignatureKeyInfo"/>.</summary>
    public const string ParsedInfoItemKey = "AAuth.ParsedSignatureKey";

    /// <summary>Internal key for JTI store stashed in HttpContext.Items.</summary>
    internal const string JtiStoreItemKey = "AAuth.JtiStore";

    /// <summary>Algorithms this server supports, emitted in unsupported_algorithm errors.</summary>
    private static readonly string[] SupportedAlgorithms = ["Ed25519", "ES256"];

    private readonly RequestDelegate _next;
    private readonly AAuthVerifier _verifier;
    private readonly ISignatureKeyResolver _resolver;
    private readonly AAuthVerificationOptions _options;

    /// <summary>Create the middleware.</summary>
    public AAuthVerificationMiddleware(
        RequestDelegate next,
        AAuthVerifier verifier,
        ISignatureKeyResolver resolver,
        MetadataClient? metadata,
        JwksClient? jwks,
        AAuthVerificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(options);
        _next = next;
        _verifier = verifier;
        _options = options;
        _tokenVerifier = CreateTokenVerifier(options);
        _resolver = resolver is DefaultSignatureKeyResolver defaultResolver
            ? defaultResolver.WithValidation(jwks, metadata, _tokenVerifier)
            : resolver;
    }

    private readonly TokenVerifier _tokenVerifier;

    private static TokenVerifier CreateTokenVerifier(AAuthVerificationOptions options)
    {
        return new TokenVerifier
        {
            EgressPolicy = options.EgressPolicy,
            ClockSkew = options.ClockSkew,
            TimeProvider = options.TimeProvider,
        };
    }

    /// <inheritdoc cref="RequestDelegate"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var req = context.Request;
        var requiredComponents = _options.RequireBodyCoverage && HasBody(req)
            ? _options.RequiredComponents.Concat(BodyComponents).Distinct(StringComparer.Ordinal).ToArray()
            : _options.RequiredComponents;

        if (!TryGetSingle(req, AAuthConstants.Headers.Signature, out var signature) ||
            !TryGetSingle(req, AAuthConstants.Headers.SignatureInput, out var signatureInput) ||
            !TryGetSingle(req, AAuthConstants.Headers.SignatureKey, out var signatureKey))
        {
            WriteFailure(context, SignatureErrorCode.InvalidSignature, requiredComponents);
            return;
        }

        // Step 1-3: Parse scheme, resolve public key, verify HTTP signature.
        IAAuthKey publicKey;
        SignatureKeyParser.ParsedSignatureKeyInfo parsedInfo;
        SignatureKeyResolution resolution;
        string replayIdentity;
        var label = _options.SignatureLabel;
        try
        {
            _verifier.ValidateInput(signatureInput, label, req.Headers.Authorization.FirstOrDefault(),
                requiredComponents);
            var scheme = SignatureKeyHeader.Parse(signatureKey, label).Scheme;
            if (!_options.AcceptedSchemes.Contains(scheme, StringComparer.Ordinal))
                throw new AAuthVerificationException(SignatureErrorCode.UnsupportedScheme, "Scheme is not accepted by this endpoint.");
            parsedInfo = SignatureKeyParser.ParseAny(signatureKey, label);
            resolution = await _resolver.ResolveAsync(parsedInfo, context.RequestAborted)
                .ConfigureAwait(false);
            publicKey = resolution.PublicKey;
            parsedInfo = resolution.Info;
            if (parsedInfo.Scheme is "jwt" or "self-jwt" && resolution.VerifiedToken is null)
                throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Resolver did not return a verified assertion.");

            var path = (req.PathBase + req.Path).ToUriComponent();
            if (string.IsNullOrEmpty(path)) { path = "/"; }

            replayIdentity = _verifier.Verify(
                method: req.Method,
                authority: req.Host.ToString(),
                path: path,
                signatureKey: signatureKey,
                signatureInput: signatureInput,
                signatureHeader: signature,
                publicKey: publicKey,
                authorization: req.Headers.Authorization.FirstOrDefault(),
                label: label,
                fields: req.Headers.ToDictionary(header => header.Key.ToLowerInvariant(), header => string.Join(", ", header.Value.ToArray())),
                requiredComponents: requiredComponents,
                keyId: resolution.KeyId,
                fieldValues: req.Headers.ToDictionary(header => header.Key.ToLowerInvariant(), header => header.Value.Select(value => value ?? "").ToArray()),
                requestScheme: req.Scheme,
                query: req.QueryString.Value ?? "",
                requestTarget: context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()?.RawTarget);
            var covered = (IReadOnlyList<StructuredFieldValues.ParsedItem>)StructuredFields.Member(signatureInput, label).Value;
            if (covered.Any(component => component.Value is "content-digest"))
            {
                var digests = StructuredFields.Dictionary(req.Headers["Content-Digest"].ToString());
                req.EnableBuffering();
                using var body = new MemoryStream();
                await req.Body.CopyToAsync(body, context.RequestAborted).ConfigureAwait(false);
                req.Body.Position = 0;
                var matched = false;
                foreach (var digest in digests)
                {
                    byte[]? hash = digest.Key switch
                    {
                        "sha-256" => System.Security.Cryptography.SHA256.HashData(body.GetBuffer().AsSpan(0, (int)body.Length)),
                        "sha-512" => System.Security.Cryptography.SHA512.HashData(body.GetBuffer().AsSpan(0, (int)body.Length)),
                        _ => null,
                    };
                    if (hash is null) continue;
                    if (digest.Value.Value is not ReadOnlyMemory<byte> expected
                        || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(hash, expected.Span))
                        throw new AAuthVerificationException(SignatureErrorCode.InvalidSignature, "Content-Digest does not match request body.");
                    matched = true;
                }
                if (!matched) throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "No supported Content-Digest member.");
            }
        }
        catch (Exception ex) when (ex is AAuthVerificationException or TokenVerificationException or JwkValidationException
            or AAuthMetadataException or System.Net.Http.HttpRequestException or FormatException or System.Text.Json.JsonException
            || ex is OperationCanceledException && !context.RequestAborted.IsCancellationRequested)
        {
            var errorCode = ex switch
            {
                AAuthVerificationException signatureException => signatureException.Code,
                TokenVerificationException tokenException => tokenException.Code,
                JwkValidationException keyException => keyException.Code,
                AAuthMetadataException metadataException => metadataException.Code,
                System.Net.Http.HttpRequestException => SignatureErrorCode.InvalidKey,
                OperationCanceledException => SignatureErrorCode.InvalidKey,
                _ => SignatureErrorCode.InvalidRequest,
            };
            WriteFailure(context, errorCode, requiredComponents);
            return;
        }

        // §Agent Token Usage: an agent token (and likewise an auth token) is an
        // externally-vouched JWT and MUST be presented via Signature-Key scheme=jwt.
        // Reject one smuggled through a self-anchored/pseudonymous scheme (jkt-jwt)
        // or a keyless inline scheme, which carry no externally-verified issuer.
        var presentedTyp = (string?)parsedInfo.Header?["typ"];
        if ((presentedTyp == AgentTokenBuilder.TokenType || presentedTyp == AuthTokenBuilder.TokenType
                || presentedTyp == PersonTokenBuilder.TokenType)
            && parsedInfo.Scheme != AAuthConstants.Schemes.Jwt)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers[SignatureError.HeaderName] =
                SignatureError.Format(SignatureErrorCode.InvalidJwt);
            context.Response.Headers[AAuthConstants.Headers.AAuthError] =
                $"{presentedTyp} MUST be presented with Signature-Key scheme=jwt.";
            return;
        }

        var tokenId = SignatureKeyParser.Text(parsedInfo.Payload, "jti");
        var createdSeconds = (long)StructuredFields.Member(signatureInput, label).Parameters["created"];
        var replayExpiry = DateTimeOffset.FromUnixTimeSeconds(createdSeconds) + _verifier.MaxAge;
        if (context.Items[JtiStoreItemKey] is IJtiStore jtiStore
            && !await jtiStore.TryRecordRequestAsync(replayIdentity, replayExpiry, context.RequestAborted).ConfigureAwait(false))
        {
            WriteFailure(context, SignatureErrorCode.InvalidJwt);
            return;
        }


        // Step 4-6: external JWT issuer verification (jwt scheme: agent/auth tokens).
        // The jkt-jwt scheme is self-anchored (draft-05 §3.4) and pseudonymous
        // (§6.3) — it carries no externally-vouched issuer, so it is excluded here;
        // its durable→ephemeral delegation is verified during key resolution.
        if (resolution.VerifiedToken is not null &&
            parsedInfo.Scheme is AAuthConstants.Schemes.Jwt &&
            parsedInfo.Jwt is not null &&
            parsedInfo.Header is not null &&
            parsedInfo.Payload is not null)
        {

            var typ = (string?)parsedInfo.Header["typ"];
            try
            {
                if (typ == AgentTokenBuilder.TokenType)
                {
                    if (!IssuerTrust.IsTrusted(_options.TrustedAgentProviderIssuers, _options.IsTrustedAgentProviderIssuer, resolution.VerifiedToken.Issuer))
                        throw new TokenVerificationException("Agent issuer is not trusted by policy.");
                }
                else if (typ == AuthTokenBuilder.TokenType)
                {
                    if (!IssuerTrust.IsTrusted(_options.TrustedAuthTokenIssuers, _options.IsTrustedAuthTokenIssuer, resolution.VerifiedToken.Issuer))
                        throw new TokenVerificationException("Auth token issuer is not trusted by policy.");
                    var audience = _options.ResourceIdentifier ?? SignatureKeyParser.Text(resolution.VerifiedToken.Payload, "aud")
                        ?? throw new TokenVerificationException("Auth token requires aud.");
                    _tokenVerifier.VerifyAuthToken(parsedInfo.Jwt, resolution.IssuerKey!, audience, publicKey,
                        accountExpectation: _options.ResourceIdentifier is null ? null
                            : new AccountExpectation(_options.ExpectedAccount?.Invoke(context)));
                }
                else if (typ == PersonTokenBuilder.TokenType)
                {
                    var trusted = _options.TrustedPersonServers is null && _options.IsTrustedPersonServer is null
                        ? IssuerTrust.IsTrusted(_options.TrustedAuthTokenIssuers, _options.IsTrustedAuthTokenIssuer, resolution.VerifiedToken.Issuer)
                        : IssuerTrust.IsTrusted(_options.TrustedPersonServers, _options.IsTrustedPersonServer, resolution.VerifiedToken.Issuer);
                    if (!trusted)
                        throw new TokenVerificationException("Person token issuer is not trusted by policy.");
                    var audience = _options.ResourceIdentifier ?? SignatureKeyParser.Text(resolution.VerifiedToken.Payload, "aud")
                        ?? throw new TokenVerificationException("Person token requires aud.");
                    _tokenVerifier.VerifyPersonToken(parsedInfo.Jwt, resolution.IssuerKey!, audience, publicKey);
                }
                // Other token types require different trust chains and are not
                // verified at this layer.
            }
            catch (TokenVerificationException ex)
            {
                WriteFailure(context, ex.Code);
                return;
            }
        }

        var inventory = context.Items[TokenStoreItemKey] as IJtiStore ?? context.Items[JtiStoreItemKey] as IJtiStore;
        if (inventory is not null && tokenId is { Length: > 0 } revocableJti &&
            resolution.VerifiedToken is { } revocableToken)
        {
            var tokenKey = new TokenKey(revocableToken.Issuer, revocableJti);
            if (await inventory.IsRevokedAsync(tokenKey, context.RequestAborted).ConfigureAwait(false))
            {
                WriteFailure(context, SignatureErrorCode.RevokedJwt);
                return;
            }
            if (revocableToken.ExpiresAt > _options.TimeProvider.GetUtcNow()
                && !await inventory.RegisterAsync(tokenKey, revocableToken.ExpiresAt, context.RequestAborted).ConfigureAwait(false))
            {
                WriteFailure(context, SignatureErrorCode.InvalidJwt);
                return;
            }
        }

        // Store both the parsed info and the verification result.
        var trustedPayload = resolution.VerifiedToken?.Payload;
        var tokenType = (string?)parsedInfo.Header?["typ"];
        var agentIdentifier = tokenType == AgentTokenBuilder.TokenType ? SignatureKeyParser.Text(trustedPayload, "sub") : null;
        var personServer = tokenType switch
        {
            PersonTokenBuilder.TokenType => resolution.VerifiedToken?.Issuer,
            AuthTokenBuilder.TokenType => SignatureKeyParser.Text(trustedPayload, "ps"),
            _ => null,
        };
        context.Items[ParsedInfoItemKey] = parsedInfo;
        context.Items[ContextItemKey] = new VerificationResult
        {
            Scheme = parsedInfo.Scheme,
            TokenType = tokenType,
            Issuer = resolution.VerifiedIdentifier,
            Agent = agentIdentifier,
            Subject = SignatureKeyParser.Text(trustedPayload, "sub"),
            Scope = SignatureKeyParser.Text(trustedPayload, "scope"),
            IssuerVerified = resolution.VerifiedToken is not null,
        };

        // Store typed verification result in HttpContext.Features for
        // AAuthAuthenticationHandler and authorization policies.
        var tokenTypeEnum = AAuthTokenTypeExtensions.ParseTokenType(tokenType);
        var level = DetermineLevel(parsedInfo.Scheme, tokenType);
        var scopeString = SignatureKeyParser.Text(trustedPayload, "scope");
        var scopes = ParseScopes(scopeString);
        var roles = ParseStringArray(trustedPayload?["roles"]);
        var groups = ParseStringArray(trustedPayload?["groups"]);

        context.Features.Set(new AAuthVerificationResult
        {
            ReplayIdentity = replayIdentity,
            ReplayExpiresAt = replayExpiry,
            Level = level,
            Scheme = parsedInfo.Scheme,
            CoveredComponents = ((IReadOnlyList<StructuredFieldValues.ParsedItem>)StructuredFields.Member(signatureInput, label).Value)
                .Where(component => !component.Parameters.ContainsKey("key") && !component.Parameters.ContainsKey("tr"))
                .Select(component => (string)component.Value).ToHashSet(StringComparer.Ordinal),
            TokenType = tokenTypeEnum,
            Issuer = resolution.VerifiedIdentifier,
            Agent = agentIdentifier,
            Subject = SignatureKeyParser.Text(trustedPayload, "sub"),
            PersonServer = personServer,
            MissionS256 = personServer is null ? null : SignatureKeyParser.Text(trustedPayload, MissionReference.ClaimName),
            Tenant = personServer is null ? null : SignatureKeyParser.Text(trustedPayload, "tenant"),
            Scopes = scopes,
            Account = tokenType == AuthTokenBuilder.TokenType ? AccountBinding.Read(trustedPayload) : null,
            AccountVerified = tokenType == AuthTokenBuilder.TokenType && _options.ResourceIdentifier is not null
                && AccountBinding.Read(trustedPayload) is not null,
            Roles = roles,
            Groups = groups,
            // For jkt-jwt the stable pseudonym is the DURABLE key's thumbprint
            // (parsedInfo.Jkt), per draft-05 §7.1 — not the rotating ephemeral
            // cnf.jwk. Other schemes report the confirmation-key thumbprint.
            Jkt = parsedInfo.Scheme == AAuthConstants.Schemes.JktJwt
                ? parsedInfo.Jkt
                : parsedInfo.ConfirmationKey?.ComputeJwkThumbprint() ?? parsedInfo.Jkt,
            IssuerVerified = resolution.VerifiedToken is not null,
        });

        // Set UpstreamAuthTokenFeature for person and auth tokens so that
        // call-chaining middleware can read the verified upstream token
        // without re-parsing Signature-Key.
        if (tokenType is AuthTokenBuilder.TokenType or PersonTokenBuilder.TokenType &&
            parsedInfo.Jwt is not null &&
            resolution.VerifiedToken is not null &&
            parsedInfo.Scheme is AAuthConstants.Schemes.Jwt)
        {
            context.Features.Set(new UpstreamAuthTokenFeature(parsedInfo.Jwt));
        }

        // Enrich the current Activity with AAuth verification tags for
        // OpenTelemetry-compatible tracing (no hard OTel dependency).
        var activity = System.Diagnostics.Activity.Current;
        if (activity is not null)
        {
            activity.SetTag(AAuthDiagnostics.TagScheme, parsedInfo.Scheme);
            activity.SetTag(AAuthDiagnostics.TagLevel, level.ToString());
            activity.SetTag(AAuthDiagnostics.TagTokenType, tokenType);
            if (resolution.VerifiedIdentifier is not null)
                activity.SetTag(AAuthDiagnostics.TagIssuer, resolution.VerifiedIdentifier);
            if (agentIdentifier is not null)
                activity.SetTag(AAuthDiagnostics.TagAgent, agentIdentifier);
            if (scopeString is not null)
                activity.SetTag(AAuthDiagnostics.TagScope, scopeString);
            activity.SetTag(AAuthDiagnostics.TagIssuerVerified,
                resolution.VerifiedToken is not null);
        }

        if (resolution.VerifiedToken is { } assertion && parsedInfo.Jwt is { } compactToken)
            context.Features.Set(new AAuthVerifiedAssertion(compactToken, assertion, publicKey));

        await _next(context).ConfigureAwait(false);
    }


    public const string TokenStoreItemKey = "AAuth.TokenInventory";

    private static readonly string[] BodyComponents = ["content-type", "content-digest"];

    // A body is present when it has a positive length, or an unknown length with
    // a content type or chunked transfer coding.
    private static bool HasBody(HttpRequest request)
        => request.ContentLength > 0
            || request.ContentLength is null
                && (request.ContentType is not null || request.Headers.ContainsKey("Transfer-Encoding"));

    private void WriteFailure(HttpContext context, SignatureErrorCode code, IReadOnlyCollection<string>? requiredComponents = null)
    {
        context.Response.StatusCode = _options.GenericSignatureKeys ? StatusCodes.Status400BadRequest : StatusCodes.Status401Unauthorized;
        context.Response.Headers[SignatureError.HeaderName] = SignatureError.Format(code,
            requiredInput: AAuthSigningHandler.CoveredComponents.Concat(requiredComponents ?? _options.RequiredComponents).Distinct().ToArray());
        if (code == SignatureErrorCode.UnsupportedAlgorithm)
            context.Response.Headers["Accept-Signature-Alg"] = string.Join(", ", SupportedAlgorithms);
        if (code == SignatureErrorCode.UnsupportedScheme)
            context.Response.Headers["Accept-Signature-Scheme"] = string.Join(", ", _options.AcceptedSchemes);
    }


    private static bool TryGetSingle(HttpRequest request, string headerName, out string value)
    {
        value = string.Empty;
        if (!request.Headers.TryGetValue(headerName, out var values) || values.Count == 0)
            return false;
        if (values.Any(string.IsNullOrEmpty))
            return false;
        value = string.Join(", ", values.Select(item => item!.Trim(' ', '\t')));
        return true;
    }


    private static AAuthLevel DetermineLevel(string scheme, string? tokenType)
    {
        if (scheme is AAuthConstants.Schemes.Hwk or AAuthConstants.Schemes.JktJwt)
            return AAuthLevel.Pseudonymous;
        if (tokenType == AuthTokenBuilder.TokenType)
            return AAuthLevel.Authorized;
        return AAuthLevel.Identified;
    }

    private static HashSet<string> ParseScopes(string? scopeString)
    {
        if (string.IsNullOrWhiteSpace(scopeString))
            return new HashSet<string>();
        return new HashSet<string>(
            scopeString.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            StringComparer.Ordinal);
    }

    private static HashSet<string> ParseStringArray(System.Text.Json.Nodes.JsonNode? node)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (node is System.Text.Json.Nodes.JsonArray array)
        {
            foreach (var item in array)
            {
                if (item is not null && item.GetValueKind() == System.Text.Json.JsonValueKind.String)
                {
                    set.Add(item.GetValue<string>());
                }
            }
        }
        return set;
    }
}

/// <summary>
/// Result of AAuth verification (HTTP sig + JWT issuer verification).
/// Stored in <see cref="HttpContext.Items"/> under
/// <see cref="AAuthVerificationMiddleware.ContextItemKey"/>.
/// </summary>
public sealed class VerificationResult
{
    /// <summary>The Signature-Key scheme (jwt, hwk, jwks_uri, jkt-jwt).</summary>
    public required string Scheme { get; init; }

    /// <summary>Token type from JWT <c>typ</c> header (aa-agent+jwt, aa-auth+jwt), or null for non-JWT schemes.</summary>
    public string? TokenType { get; init; }

    /// <summary>Issuer (<c>iss</c>) from the JWT, or null for non-JWT schemes.</summary>
    public string? Issuer { get; init; }

    /// <summary>Agent identifier from the JWT, or null.</summary>
    public string? Agent { get; init; }

    /// <summary>Subject (<c>sub</c>) from the JWT, or null.</summary>
    public string? Subject { get; init; }

    /// <summary>Scope (<c>scope</c>) from the JWT, or null.</summary>
    public string? Scope { get; init; }

    /// <summary>Whether the JWT issuer's signature was verified against JWKS.</summary>
    public bool IssuerVerified { get; init; }
}

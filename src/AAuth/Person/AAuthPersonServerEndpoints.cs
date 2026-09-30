using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Access;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Governance;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AAuth.Person;

/// <summary>
/// Configuration for a Person Server registered with <c>AddAAuthPersonServer</c> and mapped
/// with <see cref="AAuthPersonServerEndpoints.MapAAuthPersonServer"/>. Bind it from
/// <c>AAuth:PersonServer</c>.
/// </summary>
public sealed class AAuthPersonServerOptions
{
    public AAuthEgressPolicy EgressPolicy { get; set; } = AAuthEgressPolicy.Production;
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    public Func<PersonPendingEntry, ClarificationRequirement, System.Threading.CancellationToken, Task<ClarificationResponse?>>? TriageClarificationAsync { get; set; }

    /// <summary>HTTPS URL of this Person Server (<c>iss</c> of minted auth tokens).</summary>
    public string Issuer { get; set; } = "";

    /// <summary>
    /// The PS signing keys, keyed by <c>kid</c>. Published at the JWKS; minted tokens are
    /// signed with the active key.
    /// </summary>
    public AAuthSigningKeySet SigningKeys { get; set; } = new();

    /// <summary>
    /// A handle in the registered <see cref="IKeyStore"/> to load the signing key from when
    /// <see cref="SigningKeys"/> is empty. Published under <see cref="KeyId"/>, or the key's
    /// thumbprint when unset.
    /// </summary>
    public string? KeyHandle { get; set; }

    /// <summary>The <c>kid</c> for the key loaded from <see cref="KeyHandle"/>.</summary>
    public string? KeyId { get; set; }

    /// <summary>
    /// Serve this instance only for requests whose <c>Host</c> is the issuer's authority.
    /// Required when several AAuth roles or instances share one host.
    /// </summary>
    public bool MatchIssuerHost { get; set; }

    /// <summary>The auth token endpoint path (<c>auth_token_endpoint</c>). Default <c>/token</c>.</summary>
    public string TokenPath { get; set; } = "/token";

    /// <summary>The person token endpoint path (<c>person_token_endpoint</c>). Default <c>/person</c>.</summary>
    public string PersonTokenPath { get; set; } = "/person";
    public string RevocationPath { get; set; } = "/revoke";
    public Action<AAuthRevocationOptions>? ConfigureRevocation { get; set; }

    /// <summary>The pending (poll) path prefix. Default <c>/pending</c>.</summary>
    public string PendingPathPrefix { get; set; } = "/pending";

    /// <summary>
    /// The fallback scope when the resource token carries none. Default empty:
    /// the spec makes <c>scope</c> OPTIONAL, so a scopeless resource token mints
    /// a scopeless auth token (still valid via its <c>sub</c>) rather than
    /// injecting an arbitrary scope.
    /// </summary>
    public string DefaultScope { get; set; } = "";
    public IReadOnlyList<string>? ScopesSupported { get; set; }

    /// <summary>
    /// The PS-hosted interaction/consent path advertised on
    /// <c>requirement=interaction</c>. Default <c>/interaction</c>. The caller
    /// maps this endpoint and resolves the verdict against the shared
    /// <see cref="IPersonPendingStore"/>.
    /// </summary>
    public string InteractionPath { get; set; } = "/interaction";
    public BrowserConsentSessions? ResourceInteractionSessions { get; set; }

    /// <summary>
    /// Trust for this Person Server. <see cref="AAuthTrustOptions.AccessServers"/> governs
    /// four-party federation. <b>Open by default (spec-compliant):</b> the PS federates
    /// to the AS named in a <em>verified</em> resource token's <c>aud</c>; §PS-AS Trust
    /// Establishment requires no separate registration step. An <b>empty</b>
    /// <see cref="AAuthTrustRule.Allowed"/> set disables the four-party branch.
    /// Upstream auth tokens are accepted from this PS, and from an Access Server only
    /// when Access Server trust is configured. Agent Provider trust applies to inbound
    /// agent tokens.
    /// </summary>
    public AAuthTrustOptions Trust { get; set; } = new();

    /// <summary>
    /// The §Interaction Endpoint path advertised in the PS metadata
    /// (<c>interaction_endpoint</c>), where agents POST mission interaction /
    /// payment / question / completion requests. Distinct from
    /// <see cref="InteractionPath"/> (the consent URL on <c>requirement=interaction</c>).
    /// When null the metadata falls back to <see cref="InteractionPath"/>.
    /// </summary>
    public string? InteractionEndpointPath { get; set; }

    /// <summary>The mission endpoint path advertised in the PS metadata (<c>mission_endpoint</c>), if any.</summary>
    public string? MissionPath { get; set; }

    /// <summary>The permission endpoint path advertised in the PS metadata (<c>permission_endpoint</c>), if any.</summary>
    public string? PermissionPath { get; set; }

    /// <summary>The audit endpoint path advertised in the PS metadata (<c>audit_endpoint</c>), if any.</summary>
    public string? AuditPath { get; set; }

    /// <summary>
    /// Additional path prefixes the mapper's request-signature verification skips,
    /// on top of <c>/.well-known</c> and the interaction path. A PS uses this to
    /// declare its own unsigned surfaces — e.g. a browser consent/admin page that
    /// records the user's decision (§PS Approval Endpoint Authentication: how the
    /// PS authenticates the approving party is out of scope, so these stay the
    /// PS's own). Prefixes are matched with <c>StartsWithSegments</c>.
    /// </summary>
    public IReadOnlyCollection<string>? UnsignedPathPrefixes { get; set; }
}

/// <summary>
/// Maps the Person Server token endpoint, pending poll endpoint, and well-known
/// metadata in one call — the three-/four-party counterpart to
/// <c>MapAAuthAccessServer</c>. The AAuth crypto (signature verification,
/// resource-token verification, the auth-token mint, the §Auth Token Delivery
/// check, and PS→AS federation) lives here; only the identity + consent
/// decision is delegated to the DI-registered
/// <see cref="IIdentityClaimsAsserter"/>. When a request carries a mission
/// claim, the host packages the mission three-gate model (terminated rejection,
/// prior-consent silent grant, and park-and-prompt) over the
/// <see cref="IMissionStore"/>/<see cref="IMissionLog"/> primitives.
/// </summary>
public static class AAuthPersonServerEndpoints
{
    /// <summary>
    /// Configure the PS pipeline: publish <c>/.well-known/aauth-person.json</c>
    /// + JWKS, add the request-signature verification middleware (excluding the
    /// well-known and interaction paths), and map the token + pending endpoints.
    /// Resolves <see cref="TokenVerifier"/>, <see cref="MetadataClient"/>,
    /// <see cref="JwksClient"/>, <see cref="IIdentityClaimsAsserter"/>, and
    /// <see cref="IPersonPendingStore"/> from DI. The mission gate additionally
    /// resolves <see cref="IMissionStore"/> and <see cref="IMissionLog"/>;
    /// call-chaining resolves <see cref="UpstreamTokenValidator"/>; the
    /// four-party branch resolves <see cref="AccessServerClient"/>.
    /// </summary>
    public static WebApplication MapAAuthPersonServer(this WebApplication app, string? name = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        name ??= AAuthPersonServerBuilder.DefaultName;
        var identity = app.Services.GetKeyedService<IAAuthServerIdentity>(name)
            ?? throw new InvalidOperationException($"No Person Server named '{name}' is registered; call AddAAuthPersonServer first.");
        var options = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<AAuthPersonServerOptions>>().Get(name);
        _ = identity.SigningKeys.Active;

        var issuer = options.Issuer;
        var (routes, inScope) = AAuthServerRoles.Scope(app, issuer, options.MatchIssuerHost);
        var inventory = RevocationEndpoint.MapIssuerRevocationCore(app, routes, inScope,
            app.Services.GetRequiredKeyedService<AAuthRevocationService>(name), options.RevocationPath, revocation =>
            {
                // A PS answers an agent provider's revocation with an empty 200.
                revocation.ReportDownstream = false;
                options.ConfigureRevocation?.Invoke(revocation);
            });
        var interactionPath = "/" + options.InteractionPath.Trim('/');
        var interactionPrefix = interactionPath.Split('/', StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } seg
            ? "/" + seg[0]
            : interactionPath;
        var interactionUrl = $"{issuer}{interactionPath}";

        var unsignedPrefixes = (options.UnsignedPathPrefixes ?? Array.Empty<string>())
            .Select(p => "/" + p.Trim('/'))
            .Where(p => p.Length > 1)
            .ToArray();

        // 1. Well-known metadata + JWKS (reachable without a signature).
        WellKnownEndpoints.MapAAuthPersonServerWellKnown(routes, new AAuthPersonServerMetadataOptions
        {
            EgressPolicy = options.EgressPolicy,
            Issuer = options.Issuer,
            AuthTokenEndpoint = $"{issuer}{options.TokenPath}",
            PersonTokenEndpoint = $"{issuer}{options.PersonTokenPath}",
            SigningKeys = options.SigningKeys,
            InteractionEndpoint = AAuthServerRoles.OptionalUrl(issuer, options.InteractionEndpointPath) ?? interactionUrl,
            MissionEndpoint = AAuthServerRoles.OptionalUrl(issuer, options.MissionPath),
            PermissionEndpoint = AAuthServerRoles.OptionalUrl(issuer, options.PermissionPath),
            AuditEndpoint = AAuthServerRoles.OptionalUrl(issuer, options.AuditPath),
            ScopesSupported = options.ScopesSupported,
            RevocationEndpoint = $"{issuer}{options.RevocationPath}",
        });

        // 2. Verification middleware. The agent signs with the jwt scheme
        //    with issuer verification; the browser-facing interaction
        //    endpoint carries no signature, so exclude it — plus any unsigned
        //    surfaces the PS declares (e.g. its own consent/admin page).
        app.UseWhen(
            ctx => inScope(ctx)
                && !ctx.Request.Path.StartsWithSegments("/.well-known")
                && !ctx.Request.Path.StartsWithSegments(options.RevocationPath)
                && !ctx.Request.Path.StartsWithSegments(interactionPrefix)
                && !unsignedPrefixes.Any(p => ctx.Request.Path.StartsWithSegments(p)),
            branch => branch.UseAAuthVerificationCore(new AAuthVerificationOptions { EgressPolicy = options.EgressPolicy,
                AcceptedSchemes = ["jwt"], RequireBodyCoverage = true, TimeProvider = options.TimeProvider,
                Trust = options.Trust }));

        var tokenVerifier = app.Services.GetRequiredKeyedService<TokenVerifier>(name);
        var metadataClient = app.Services.GetRequiredService<MetadataClient>();
        var jwksClient = app.Services.GetRequiredService<JwksClient>();
        var asserter = app.Services.GetRequiredKeyedService<IIdentityClaimsAsserter>(name);
        var store = app.Services.GetRequiredKeyedService<IPersonPendingStore>(name);
        var observers = app.Services.GetKeyedServices<IPersonPendingObserver>(name)
            .Concat(app.Services.GetServices<IPersonPendingObserver>()).Distinct().ToArray();
        var pending = observers.Length == 0 ? store : new ObservedPersonPendingStore(store, observers);
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AAuth.PersonServer");
        PersonResourceInteraction.Map(routes, pending, options);
        AAuthServerRoles.WarnOnInMemoryDefaults(app.Services, logger, "Person Server", name, store, inventory,
            app.Services.GetService<IMissionStore>(), app.Services.GetService<IMissionLog>());

        // Startup footgun guard (diagnostics only): warn when federation is open by
        // default. Suppressed by any explicit policy (including AAuthTrust.Any).
        TrustConfigDiagnostics.WarnIfOpenFederation(
            logger,
            trustConfigured: options.Trust.IsConfigured(AAuthTrustedParty.AccessServer, app.Services),
            "MapAAuthPersonServer",
            "this Person Server federates to any Access Server named in a verified resource token's aud " +
            "because no Trust.AccessServers policy is configured (the AAuth spec " +
            "default). Configure a policy to restrict, or assign AAuthTrust.Any to declare intentional open " +
            "federation and silence this warning.");

        // An upstream auth token is this PS's own, or from an Access Server the PS is
        // configured to trust; open federation does not extend to upstream tokens.
        async ValueTask<bool> IsTrustedAuthTokenIssuer(string candidate, HttpContext ctx)
            => string.Equals(candidate, issuer, StringComparison.Ordinal)
                || (options.Trust.IsConfigured(AAuthTrustedParty.AccessServer, ctx.RequestServices)
                    && await options.Trust.IsTrustedAsync(candidate, AAuthTrustedParty.AccessServer,
                        ctx.RequestServices, ctx, AuthTokenBuilder.TokenType, ctx.RequestAborted).ConfigureAwait(false));

        // Presented and upstream person tokens are this PS's own: verify them with
        // its signing keys rather than fetching its own JWKS.
        var selfVerifier = tokenVerifier.WithLocalIssuer(issuer, options.SigningKeys);

        Task<IResult> MintEntry(PersonPendingEntry entry) => entry.PersonToken
            ? AuthTokenResponse.CreateTrackedAsync(ct => MintPerson(ct,
                entry.ResourceUrl,
                entry.Subject ?? throw new TokenVerificationException("Approved identity assertion is missing its directed subject."),
                entry.Tenant, entry.AgentConfirmationKey!, entry.MissionS256,
                entry.AgentTokenExpiresAt, entry.AuthorizationExpiresAt),
                entry.ExpiresAt, inventory, entry.SourceTokens, "person_token", options.TimeProvider)
            : AuthTokenResponse.CreateTrackedAsync(ct => MintAuth(ct,
                entry.ResourceUrl, entry.Scope, entry.AgentConfirmationKey!,
                entry.PersonSubject ?? throw new TokenVerificationException("Pending request is missing its verified subject."),
                entry.PersonTenant, entry.Roles, entry.Groups, entry.AdditionalClaims, entry.MissionS256,
                entry.AgentTokenExpiresAt, entry.AuthorizationExpiresAt, entry.Account),
                entry.ExpiresAt, inventory, entry.SourceTokens, options.TimeProvider);

        ValueTask<string> MintPerson(CancellationToken cancellationToken,
            string resource, string subject, string? tenant, IAAuthKey confirmationKey, string? missionS256,
            DateTimeOffset agentTokenExpiresAt, DateTimeOffset? authorizationExpiresAt)
        {
            var (signingKid, signingKey) = options.SigningKeys.Active;
            return new PersonTokenBuilder
            {
                EgressPolicy = options.EgressPolicy,
                Issuer = issuer,
                Audience = resource,
                Subject = subject,
                Tenant = tenant,
                ConfirmationKey = confirmationKey,
                MissionS256 = missionS256,
                AgentTokenExpiresAt = agentTokenExpiresAt,
                AuthorizationExpiresAt = authorizationExpiresAt,
                TimeProvider = options.TimeProvider,
                Key = signingKey,
                KeyId = signingKid,
            }.BuildAsync(cancellationToken);
        }

        // The auth token's sub, tenant and mission_s256 are the verified resource
        // token's (copied from the presented token); the asserter only decides
        // consent and releases roles/groups/additional claims.
        ValueTask<string> MintAuth(CancellationToken cancellationToken,
            string resourceUrl, string scope, IAAuthKey confirmationKey,
            string subject, string? tenant, IReadOnlyList<string>? roles, IReadOnlyList<string>? groups,
            IReadOnlyDictionary<string, JsonNode?>? additionalClaims, string? missionS256,
            DateTimeOffset agentTokenExpiresAt, DateTimeOffset? authorizationExpiresAt, string? account = null)
        {
            var (signingKid, signingKey) = options.SigningKeys.Active;
            return new AuthTokenBuilder
            {
                EgressPolicy = options.EgressPolicy,
                Issuer = issuer,
                PersonServer = issuer,
                Audience = resourceUrl,
                Account = account,
                AgentConfirmationKey = confirmationKey,
                AgentTokenExpiresAt = agentTokenExpiresAt,
                AuthorizationExpiresAt = authorizationExpiresAt,
                TimeProvider = options.TimeProvider,
                Key = signingKey,
                KeyId = signingKid,
                Subject = subject,
                Scope = scope,
                Tenant = tenant,
                Roles = roles,
                Groups = groups,
                AdditionalClaims = additionalClaims,
                MissionS256 = missionS256,
            }.BuildAsync(cancellationToken);
        }

        // Shared front half of both PS token endpoints: an agent-token carrier,
        // a JSON body, and the verified agent / sub-agent / upstream context.
        async Task<(AgentIssuanceContext? Issuance, JsonObject? Body, IResult? Failure)> ReadAgentRequestAsync(HttpContext ctx)
        {
            // Only an agent token may call a PS token endpoint — a signature-verified
            // carrier of another type is an authorization refusal (403), not a 401.
            if (ctx.GetAAuthTokenType() != AAuthTokenType.AgentToken)
            {
                return (null, null, AAuthProblemDetails.Create("invalid_request",
                    $"expected {AAuthConstants.TokenTypes.AgentToken}, got {ctx.GetAAuthTokenType()}", statusCode: StatusCodes.Status403Forbidden));
            }
            var parsed = ctx.GetAAuthParsedKey()!;
            // §Single-Level Depth: a sub-agent cannot request on its own behalf.
            if (parsed.Payload?["parent_agent"] is not null)
            {
                return (null, null, AAuthProblemDetails.Create("invalid_request",
                    "a sub-agent MUST NOT request authorization directly; the parent mediates (§Sub-Agents)", statusCode: StatusCodes.Status400BadRequest));
            }
            JsonObject? body;
            try { body = await TokenRequestBody.ReadAsync(ctx.Request, tokenVerifier); }
            catch (System.Text.Json.JsonException)
            {
                return (null, null, AAuthProblemDetails.Create("invalid_request", "body is not valid JSON", statusCode: StatusCodes.Status400BadRequest));
            }
            catch (TokenVerificationException ex) { return (null, null, AAuthProblemDetails.TokenFailure(ex)); }
            if (body is null)
                return (null, null, AAuthProblemDetails.Create("invalid_request", "missing JSON body", statusCode: StatusCodes.Status400BadRequest));
            try
            {
                var issuance = await AgentIssuanceContext.VerifyAsync(parsed.Jwt!,
                    StringMember(body, "subagent_token"), StringMember(body, "upstream_token"), issuer,
                    selfVerifier, metadataClient, jwksClient, (candidate, _) => IsTrustedAuthTokenIssuer(candidate, ctx), ctx.RequestAborted);
                return (issuance, body, null);
            }
            catch (TokenVerificationException ex) { return (null, body, AAuthProblemDetails.TokenFailure(ex)); }
        }

        // §Resource Token Verification steps 1–3: the resource token is audienced to
        // the recipient, bound to the key the issued token will carry, names this PS
        // as `ps`, and pairs with the presented token by jti/ps/sub/mission/tenant.
        async Task<(TokenVerifier.VerifiedToken Resource, TokenVerifier.VerifiedToken Presented)> VerifyPairAsync(
            string resourceTokenJwt, string presentedTokenJwt, string expectedAudience, string agentJkt,
            System.Threading.CancellationToken ct)
        {
            TokenVerifier.VerifiedToken resource;
            try
            {
                resource = await tokenVerifier.VerifyResourceTokenAsync(resourceTokenJwt, expectedAudience, agentJkt,
                    metadataClient, jwksClient, expectedPersonServer: issuer, cancellationToken: ct);
                _ = resource.Account;
            }
            catch (TokenVerificationException ex)
            { throw new TokenVerificationException(ex.Message, ex) { Credential = TokenCredential.Resource }; }
            // §Token Revocation: a resource token its resource withdrew never backs an auth token.
            if (await inventory.IsRevokedAsync(TokenRegistration.FromVerified(resource).Token, ct))
                throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.RevokedJwt,
                    "The resource token has been revoked.") { Credential = TokenCredential.Resource };
            var presented = await selfVerifier.VerifyPresentedTokenAsync(presentedTokenJwt, resource, metadataClient, jwksClient, ct);
            return (resource, presented);
        }

        // A pending request started against a resource token its resource then withdrew
        // terminates with polling error `revoked` (#token-revocation).
        async Task<IResult?> WithdrawnResourceAsync(string? resourceTokenJwt, System.Threading.CancellationToken ct)
        {
            if (resourceTokenJwt is null) return null;
            var key = TokenRegistration.FromPayload(TokenVerifier.DecodeJsonSegment(resourceTokenJwt.Split('.')[1], "payload")).Token;
            return await inventory.IsRevokedAsync(key, ct)
                ? AAuthProblemDetails.Create("revoked", "The resource token was revoked.", statusCode: StatusCodes.Status403Forbidden)
                : null;
        }

        async Task<(IReadOnlyList<TokenRegistration>? Sources, IResult? Failure)> RegisterSourcesAsync(
            AgentIssuanceContext issuance, TokenVerifier.VerifiedToken? presented, string? missionS256, System.Threading.CancellationToken ct)
        {
            var registrations = new List<TokenRegistration>(issuance.SourceTokens);
            if (presented is not null) registrations.Add(TokenRegistration.FromVerified(presented, TokenCredential.Presented));
            // A chained request neither uses nor establishes a binding (#agent-person-binding).
            if (issuance.Upstream is null) registrations.Add(AgentPersonBinding.Registration(issuer, issuance.AgentIssuer, issuance.AgentId));
            AddCascadeIndexes(registrations, issuance.AgentIssuer, issuance.AgentId, missionS256);
            try
            {
                await TokenRegistration.RegisterAsync(inventory, registrations, ct);
                await inventory.RecordSubjectAsync(issuance.SourceTokens[0].Token, issuance.AgentId, ct);
                return (registrations, null);
            }
            catch (TokenVerificationException ex) { return (null, AAuthProblemDetails.SourceRevoked(ex)); }
        }

        // #revocation-cascade Records: what the PS issues to an agent is found again by its sub and mission.
        void AddCascadeIndexes(List<TokenRegistration> registrations, string agentIssuer, string agentId, string? missionS256)
        {
            registrations.Add(RevocationRecords.Registration(RevocationRecords.Subject(issuer, agentIssuer, agentId)));
            if (missionS256 is not null)
                registrations.Add(RevocationRecords.Registration(RevocationRecords.Mission(issuer, missionS256)));
        }

        static IReadOnlyList<TokenKey> Keys(IReadOnlyList<TokenRegistration> sources) => sources.Select(source => source.Token).ToArray();
        IResult? MissionExpired(string? missionS256) => missionS256 is null ? null
            : GovernanceEndpoints.MissionTerminated(AAuthConstants.MissionTerminationReasons.Expired);

        // §Mission Status Errors: every mission_terminated carries mission_status,
        // and termination_reason when the PS knows it (the detail of its own throw).
        static IResult ExchangeFailure(string error, string? detail, int status)
            => error == AAuthMissionTerminatedException.ErrorCode
                ? GovernanceEndpoints.MissionTerminated(detail)
                : AAuthProblemDetails.Create(error, detail, statusCode: status);

        static DateTimeOffset Earliest(DateTimeOffset left, DateTimeOffset right) => left < right ? left : right;

        bool IsResourceIdentifier([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? resource) => resource is not null
            && AAuthUrl.IsHttpsOrLoopback(resource, options.EgressPolicy)
            && Uri.TryCreate(resource, UriKind.Absolute, out var resourceUri)
            && string.IsNullOrEmpty(resourceUri.Query) && string.IsNullOrEmpty(resourceUri.Fragment);

        // §Mission Approval `person_tokens`: the /person mint for each approved resource the
        // asserter asserts silently, tracked as a grant of the agent token.
        async Task<IReadOnlyDictionary<string, string>> IssueMissionPersonTokensAsync(
            MissionPersonTokenRequest request, System.Threading.CancellationToken ct)
        {
            var tokens = new Dictionary<string, string>(StringComparer.Ordinal);
            if (request.PersonServer != issuer || request.SourceTokens.Count == 0 || !MissionReference.IsValid(request.MissionS256))
                return tokens;
            IReadOnlyList<TokenKey> sources;
            try
            {
                var agentIssuer = request.SourceTokens[0].Token.Issuer;
                var registrations = new List<TokenRegistration>(request.SourceTokens)
                {
                    AgentPersonBinding.Registration(issuer, agentIssuer, request.AgentId),
                };
                AddCascadeIndexes(registrations, agentIssuer, request.AgentId, request.MissionS256);
                sources = await TokenRegistration.RegisterAsync(inventory, registrations, ct);
                await inventory.RecordSubjectAsync(request.SourceTokens[0].Token, request.AgentId, ct);
            }
            catch (TokenVerificationException) { return tokens; }
            var ceiling = request.MissionExpiresAt is { } missionExpiry
                ? Earliest(request.AgentTokenExpiresAt, missionExpiry) : request.AgentTokenExpiresAt;
            var thumbprint = request.ConfirmationKey.ComputeJwkThumbprint();
            foreach (var resource in request.Resources.Distinct(StringComparer.Ordinal))
            {
                if (!IsResourceIdentifier(resource)) continue;
                var assertion = await asserter.AssertAsync(new IdentityAssertionRequest
                {
                    PersonTokenRequest = true,
                    ResourceUrl = resource,
                    Scope = string.Empty,
                    AgentId = request.AgentId,
                    AgentKeyThumbprint = thumbprint,
                    MissionS256 = request.MissionS256,
                }, ct);
                if (assertion.Kind != IdentityAssertionKind.Assert || string.IsNullOrWhiteSpace(assertion.Subject)) continue;
                var (token, _) = await AuthTokenResponse.MintTrackedAsync(ct => MintPerson(ct,
                    resource, assertion.Subject, assertion.Tenant, request.ConfirmationKey, request.MissionS256,
                    request.AgentTokenExpiresAt, ceiling), ceiling, inventory, sources, options.TimeProvider,
                    AuthTokenResponse.Expired, ct);
                if (token is not null) tokens[resource] = token;
            }
            return tokens;
        }
        if (app.Services.GetService<IMissionPersonTokenIssuer>() is AttachableMissionPersonTokenIssuer missionIssuer)
            missionIssuer.Issue = IssueMissionPersonTokensAsync;

        // -------------------------------------------------------------------
        // POST {PersonTokenPath} — the PS person token endpoint (§Person Token Endpoint).
        // -------------------------------------------------------------------
        routes.MapPost(options.PersonTokenPath, async (HttpContext ctx) =>
        {
            var (issuance, body, failure) = await ReadAgentRequestAsync(ctx);
            if (failure is not null) return failure;

            var resource = StringMember(body, "resource");
            if (!IsResourceIdentifier(resource))
            {
                return AAuthProblemDetails.Create("invalid_request", "resource must be an HTTPS server identifier", statusCode: StatusCodes.Status400BadRequest);
            }

            string? missionS256 = null;
            if (body!.ContainsKey("mission_s256"))
            {
                if (issuance!.Upstream is not null)
                    return AAuthProblemDetails.Create("invalid_request", "mission_s256 is not sent with upstream_token; the upstream token carries the mission", statusCode: StatusCodes.Status400BadRequest);
                missionS256 = StringMember(body, "mission_s256");
                if (!MissionReference.IsValid(missionS256))
                    return AAuthProblemDetails.Create("invalid_request", "mission_s256 is malformed", statusCode: StatusCodes.Status400BadRequest);
            }
            missionS256 ??= issuance!.Upstream?.MissionS256;
            DateTimeOffset? missionExpiresAt = null;
            if (missionS256 is not null)
            {
                try { missionExpiresAt = (await ValidateMissionAsync(missionS256, issuance!.AgentId, issuance.Upstream)).ExpiresAt; }
                catch (AAuthTokenExchangeException ex)
                { return ExchangeFailure(ex.ErrorCode, ex.Detail, ex.StatusCode); }
            }
            var ceiling = missionExpiresAt is { } missionExpiry ? Earliest(issuance!.ExpiresAt, missionExpiry) : issuance!.ExpiresAt;

            var (registered, sourceFailure) = await RegisterSourcesAsync(issuance, presented: null, missionS256, ctx.RequestAborted);
            if (sourceFailure is not null) return sourceFailure;
            var sources = registered!;

            var prompt = StringMember(body, "prompt");
            var capabilities = ParseStringArray(body["capabilities"] as JsonArray);
            if (!TryReadAgentAsserted(body, out var agentAsserted))
                return AAuthProblemDetails.Create("invalid_request", "justification, platform and device must be strings", statusCode: StatusCodes.Status400BadRequest);
            var assertion = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                PersonTokenRequest = true,
                ResourceUrl = resource,
                Scope = string.Empty,
                AgentId = issuance.AgentId,
                AgentKeyThumbprint = issuance.ConfirmationKey.ComputeJwkThumbprint(),
                MissionS256 = missionS256,
                LoginHint = StringMember(body, "login_hint"),
                Prompt = prompt,
                Capabilities = capabilities,
                AgentAsserted = agentAsserted,
                UpstreamAuthorization = issuance.Upstream,
            }, ctx.RequestAborted);
            switch (assertion.Kind)
            {
                case IdentityAssertionKind.Assert:
                    if (string.IsNullOrWhiteSpace(assertion.Subject))
                        return AAuthProblemDetails.Create("server_error", "The identity asserter returned no directed subject.", statusCode: StatusCodes.Status500InternalServerError);
                    return await AuthTokenResponse.CreateTrackedAsync(ct => MintPerson(ct,
                        resource, assertion.Subject, assertion.Tenant, issuance.ConfirmationKey, missionS256,
                        issuance.AgentTokenExpiresAt, ceiling), ceiling, inventory, sources, "person_token",
                        options.TimeProvider, ctx.RequestAborted, MissionExpired(missionS256));
                case IdentityAssertionKind.Deny:
                    return AAuthProblemDetails.Create("denied", assertion.Reason, statusCode: StatusCodes.Status403Forbidden);
                case IdentityAssertionKind.NeedsConsent:
                default:
                    var entry = pending.Add(resource, string.Empty, issuance.AgentId, issuance.ConfirmationKey,
                        issuance.AgentTokenExpiresAt, missionS256, ceiling);
                    entry.PersonToken = true;
                    BindOwner(ctx, entry);
                    entry.SourceTokens = Keys(sources);
                    entry.UpstreamAuthorization = issuance.Upstream;
                    entry.Prompt = prompt;
                    entry.Capabilities = capabilities;
                    entry.AgentAsserted = agentAsserted;
                    return Pending202(ctx, entry, options, interactionUrl);
            }
        });

        // -------------------------------------------------------------------
        // POST {TokenPath} — the PS auth token endpoint (§Auth Token Request).
        // -------------------------------------------------------------------
        routes.MapPost(options.TokenPath, async (HttpContext ctx) =>
        {
            var (issuance, body, failure) = await ReadAgentRequestAsync(ctx);
            if (failure is not null) return failure;

            var resourceTokenJwt = StringMember(body, "resource_token");
            if (string.IsNullOrEmpty(resourceTokenJwt))
                return AAuthProblemDetails.Create("invalid_request", "missing resource_token", statusCode: StatusCodes.Status400BadRequest);
            var presentedTokenJwt = StringMember(body, "presented_token");
            if (string.IsNullOrEmpty(presentedTokenJwt))
                return AAuthProblemDetails.Create("invalid_request", "missing presented_token", statusCode: StatusCodes.Status400BadRequest);

            // §Auth Token Request: optional consent-shaping params. Both are tolerant —
            // unknown values flow to the asserter, which MAY honor or ignore them.
            var prompt = StringMember(body, "prompt");
            var capabilities = ParseStringArray(body!["capabilities"] as JsonArray);
            if (!TryReadAgentAsserted(body, out var agentAsserted))
                return AAuthProblemDetails.Create("invalid_request", "justification, platform and device must be strings", statusCode: StatusCodes.Status400BadRequest);

            // Route on the resource token's `aud` (peeked, not trusted; both
            // branches fully verify the token afterwards). `aud == this PS` →
            // three-party collapsed mint; `aud == an AS` → four-party federation.
            string? resourceAudience;
            try { resourceAudience = PeekJwtAudience(resourceTokenJwt, tokenVerifier); }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.Create("invalid_resource_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }
            if (resourceAudience is not null
                && !string.Equals(resourceAudience, issuer, StringComparison.Ordinal))
            {
                return await HandleFederatedAsync(ctx, issuance!, resourceTokenJwt, presentedTokenJwt, body,
                    resourceAudience, prompt, capabilities, agentAsserted);
            }

            return await HandleThreePartyAsync(ctx, issuance!, resourceTokenJwt, presentedTokenJwt, prompt, capabilities, agentAsserted);
        });

        // -------------------------------------------------------------------
        // GET {PendingPathPrefix}/{id} — the agent polls the deferred verdict.
        // -------------------------------------------------------------------
        routes.MapGet($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return AAuth.Server.DeferredState.Missing(id);
            if (!RequesterMatches(ctx, entry))
            {
                return AAuthProblemDetails.Create("unknown_interaction", statusCode: StatusCodes.Status404NotFound);
            }

            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                if (entry.ExpiresAt.ToUnixTimeSeconds() <= options.TimeProvider.GetUtcNow().ToUnixTimeSeconds())
                    return AuthTokenResponse.Expired();
                if (entry.MissionS256 is { } pendingMission
                    && await app.Services.GetRequiredService<IMissionStore>().GetAsync(pendingMission)
                        is { State: MissionState.Terminated })
                {
                    entry.FederationCancellation.Cancel();
                    return GovernanceEndpoints.MissionTerminated();
                }
                if (await WithdrawnResourceAsync(entry.ResourceToken, ctx.RequestAborted) is { } withdrawn)
                {
                    entry.FederationCancellation.Cancel();
                    return withdrawn;
                }
                if (entry.ResourceInteraction is { Error: not null } failedResource)
                    return AAuthProblemDetails.Create(failedResource.Error, statusCode: failedResource.ErrorStatus);
                if (entry.AwaitingResourceInteraction)
                    return Pending202(ctx, entry, options, interactionUrl);
                if (entry.ResumeAuthorization is { } resume)
                {
                    entry.ResumeAuthorization = null;
                    return await resume(ctx);
                }
                if (entry.MissionGate)
                {
                    return await ResolveMissionGateAsync(ctx, entry);
                }

                // Four-party entries resolve via the background federation task.
                if (entry.AgentConfirmationKey is null)
                {
                    if (entry.Status == PersonPendingStatus.AwaitingClarification)
                        return Pending202Clarification(ctx, entry, options);
                    if (entry.Status == PersonPendingStatus.Allowed && entry.AuthToken is not null)
                    {
                        return await AuthTokenResponse.CreateTrackedAsync(_ => ValueTask.FromResult(entry.AuthToken), entry.ExpiresAt,
                            inventory, entry.SourceTokens, options.TimeProvider, ctx.RequestAborted);
                    }
                    if (entry.Status == PersonPendingStatus.Denied)
                    {
                        if (!string.IsNullOrEmpty(entry.ErrorLocation))
                        {
                            ctx.Response.Headers.Location = entry.ErrorLocation;
                        }
                        return ExchangeFailure(entry.Error ?? "denied", null, entry.ErrorStatus ?? StatusCodes.Status403Forbidden);
                    }
                    // §Deferred Responses: AAuth-Requirement is present only when the person
                    // must act. Waiting on the AS (e.g. after a clarification answer) asks
                    // nothing of the person, so the PS does not re-advertise its own code.
                    if (!entry.AwaitingFederationConsent && entry.InteractionUrl is null)
                        return PendingWithoutRequirement(ctx, entry, options);
                    return Pending202(ctx, entry, options, interactionUrl);
                }

                // Three-party and person-token entries resolve when the host's
                // interaction page marks the verdict against the shared store.
                switch (entry.Status)
                {
                    case PersonPendingStatus.Allowed:
                        return await MintEntry(entry);
                    case PersonPendingStatus.Denied:
                        return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);
                    case PersonPendingStatus.Pending:
                    default:
                        return Pending202(ctx, entry, options, interactionUrl);
                }
            });
        });

        // POST {PendingPathPrefix}/{id} — the agent answers a clarification
        // (§Agent Response to Clarification) or replaces its request. The SDK
        // records it in the mission log and readies the next review.
        routes.MapPost($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return AAuth.Server.DeferredState.Missing(id);
            if (!RequesterMatches(ctx, entry))
            {
                return AAuthProblemDetails.Create("unknown_interaction", statusCode: StatusCodes.Status404NotFound);
            }
            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                if (entry.Status == PersonPendingStatus.Withdrawn)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("request_withdrawn", statusCode: StatusCodes.Status410Gone);
                }

                JsonObject? body;
                try { body = await TokenRequestBody.ReadAsync(ctx.Request, tokenVerifier); }
                catch (System.Text.Json.JsonException)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
                }
                catch (TokenVerificationException ex) { return AAuthProblemDetails.TokenFailure(ex); }

                var action = StringMember(body, "action");
                var answer = StringMember(body, "clarification_response");
                var updatedResourceToken = StringMember(body, "resource_token");
                var updatedPresentedToken = StringMember(body, "presented_token");
                if (entry.Status != PersonPendingStatus.AwaitingClarification
                    || action is not ("clarification_response" or "updated_request")
                    || (action == "clarification_response" && (string.IsNullOrWhiteSpace(answer) || body!.ContainsKey("resource_token")))
                    || (action == "updated_request" && (string.IsNullOrWhiteSpace(updatedResourceToken)
                        || string.IsNullOrWhiteSpace(updatedPresentedToken) || body!.ContainsKey("clarification_response")))
                    || (body!.ContainsKey("justification") && StringMember(body, "justification") is null))
                {
                    return AAuthProblemDetails.Create("invalid_request", "Expected a matching clarification action and payload on an awaiting clarification request.", statusCode: StatusCodes.Status400BadRequest);
                }
                if (entry.ClarificationRounds >= ClarificationExchange.DefaultMaxRounds)
                {
                    entry.Status = PersonPendingStatus.Denied;
                    return AAuthProblemDetails.Create("denied", "Clarification round limit reached.", statusCode: StatusCodes.Status403Forbidden);
                }
                if (action == "updated_request")
                {
                    try
                    {
                        var (replacement, _) = await VerifyPairAsync(updatedResourceToken!, updatedPresentedToken!,
                            entry.ResourceAudience!, entry.ResourceKeyThumbprint!, ctx.RequestAborted);
                        RequireSameRequest(entry.ResourceContext!, replacement.Payload);
                        if (!AccountBinding.Matches(entry.Account, replacement.Account))
                            throw new TokenVerificationException("Changing account requires a new authorization request.")
                            { Credential = TokenCredential.Resource };
                        var replacementInteraction = await PersonResourceInteraction.CreateAsync(replacement.Payload,
                            updatedResourceToken!, options.EgressPolicy, ctx.RequestAborted);
                        entry.Scope = (string?)replacement.Payload["scope"] ?? options.DefaultScope;
                        entry.ResourceToken = updatedResourceToken;
                        entry.PresentedToken = updatedPresentedToken;
                        entry.ResourceContext = (JsonObject)replacement.Payload.DeepClone();
                        entry.ResourceInteraction = replacementInteraction;
                        if (replacementInteraction is not null) entry.InteractionUrl = interactionUrl + "/resource";
                    }
                    catch (TokenVerificationException ex)
                    {
                        return AAuthProblemDetails.TokenFailure(ex, TokenCredential.Resource);
                    }
                }
                entry.ClarificationRounds++;
                if (StringMember(body, "justification") is { } justification)
                    entry.ClarificationAnswers.Add(justification);
                if (answer is not null)
                {
                    entry.ClarificationAnswers.Add(answer);
                }
                var missionLog = app.Services.GetRequiredService<IMissionLog>();
                if (entry.MissionS256 is not null) await missionLog.AppendAsync(new MissionLogEntry(
                    entry.MissionS256, MissionLogEntryKind.Clarification, DateTimeOffset.UtcNow)
                {
                    Detail = answer ?? "updated_request",
                });
                // The clarification round is answered — re-review on the next poll.
                entry.ClarificationQuestion = null;
                entry.ClarificationDeadline = null;
                entry.Status = PersonPendingStatus.Pending;
                entry.Browser.Renew();
                entry.FederationAnswer?.TrySetResult(action == "updated_request"
                    ? ClarificationResponse.Update(updatedResourceToken!, updatedPresentedToken!, StringMember(body, "justification"))
                    : ClarificationResponse.Respond(answer!));
                return Results.NoContent();
            });
        });

        // DELETE {PendingPathPrefix}/{id} — the agent withdraws the request
        // (§Agent Response to Clarification — cancel). A later poll returns 410.
        routes.MapDelete($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return AAuth.Server.DeferredState.Missing(id);
            if (!RequesterMatches(ctx, entry))
            {
                return AAuthProblemDetails.Create("unknown_interaction", statusCode: StatusCodes.Status404NotFound);
            }
            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                entry.Status = PersonPendingStatus.Withdrawn;
                entry.Lifecycle.Cancel();
                entry.FederationCancellation.Cancel();
                var missionLog = app.Services.GetRequiredService<IMissionLog>();
                if (entry.MissionS256 is not null) await missionLog.AppendAsync(new MissionLogEntry(
                    entry.MissionS256, MissionLogEntryKind.Clarification, DateTimeOffset.UtcNow)
                {
                    Detail = "cancelled",
                });
                return Results.NoContent();
            });
        });

        return app;

        // ---- mission-gate resolution (gate 2c) -----------------------------
        // §Person Token Endpoint / §Resource Token Verification step 4: the mission
        // exists, is active, and belongs to this agent — or, when chaining, is the
        // mission the verified upstream token carries under this PS.
        async Task<StoredMission> ValidateMissionAsync(string missionS256, string consentAgentId, UpstreamTokenValidationResult? upstream)
        {
            var stored = await app.Services.GetRequiredService<IMissionStore>().GetAsync(missionS256);
            var authorized = stored is not null && stored.PersonServer == issuer
                && (stored.Agent == consentAgentId
                    || upstream is { IsValid: true } && upstream.MissionS256 == missionS256);
            if (!authorized)
                throw new AAuthTokenExchangeException("mission_not_found", null, StatusCodes.Status404NotFound, true);
            if (stored!.State == MissionState.Terminated)
                throw new AAuthTokenExchangeException("mission_terminated", null, StatusCodes.Status403Forbidden, true);
            // The detail carries the termination_reason ExchangeFailure reports.
            if (stored.ExpiresAt is { } expiresAt && expiresAt.ToUnixTimeSeconds() <= options.TimeProvider.GetUtcNow().ToUnixTimeSeconds())
                throw new AAuthTokenExchangeException("mission_terminated", AAuthConstants.MissionTerminationReasons.Expired,
                    StatusCodes.Status403Forbidden, true);
            return stored;
        }

        async Task<(MissionTokenConsentDecision Decision, string Detail)> ReviewMissionAsync(MissionTokenConsentContext context)
        {
            var approval = await ValidateMissionAsync(context.MissionS256, context.ConsentAgentId ?? context.AgentId, context.UpstreamAuthorization);
            var missionLog = app.Services.GetRequiredService<IMissionLog>();
            // §Mission Update: from acceptance on, the mission means the approved blob
            // plus its accepted updates. A consent recorded before the latest update was
            // given against the older meaning, so it no longer grants silently.
            var history = await missionLog.ReadAsync(context.MissionS256);
            var updates = history.Where(entry => entry.Kind == MissionLogEntryKind.Update).ToArray();
            var sinceUpdate = updates.Length == 0 ? history
                : history.Skip(history.ToList().LastIndexOf(updates[^1]) + 1).ToArray();
            if (context.Stage == MissionTokenConsentStage.Gate
                && await missionLog.HasPriorConsentAsync(
                    context.MissionS256, context.ResourceUrl, context.Scope, account: context.Account,
                    agentId: context.AgentId, agentKeyThumbprint: context.AgentKeyThumbprint)
                && (updates.Length == 0 || sinceUpdate.Any(entry => entry.Kind == MissionLogEntryKind.Token && entry.Granted == true
                    && AccountBinding.Matches(entry.Account, context.Account)
                    && entry.AgentId == context.AgentId && entry.AgentKeyThumbprint == context.AgentKeyThumbprint
                    && entry.Resource == context.ResourceUrl && entry.Scope == context.Scope)))
                return (MissionTokenConsentDecision.Grant(), "PriorConsent");
            return (await app.Services.GetRequiredService<IMissionTokenConsent>().ReviewAsync(
                context with { ValidatedApproval = approval, AcceptedUpdates = updates }), "InScope");
        }

        async Task<IResult> ResolveMissionGateAsync(HttpContext ctx, PersonPendingEntry entry)
        {
            if (entry.MissionS256 is not { } s256)
                return Pending202(ctx, entry, options, interactionUrl);
            try { await ValidateMissionAsync(s256, entry.ConsentAgentId, entry.UpstreamAuthorization); }
            catch (AAuthTokenExchangeException ex)
            {
                entry.FederationMissionConsent?.TrySetException(ex);
                return ExchangeFailure(ex.ErrorCode, ex.Detail, ex.StatusCode);
            }
            var missionLog = app.Services.GetRequiredService<IMissionLog>();

            switch (entry.Status)
            {
                case PersonPendingStatus.Withdrawn:
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    return AAuth.Server.AAuthProblemDetails.Create("request_withdrawn", statusCode: StatusCodes.Status410Gone);

                case PersonPendingStatus.AwaitingClarification:
                    return Pending202Clarification(ctx, entry, options);

                case PersonPendingStatus.Allowed:
                    // Resolved out-of-band by the PS's user channel (MarkAllowed).
                    return await MintMissionEntryAsync(entry);

                case PersonPendingStatus.Denied:
                    entry.FederationMissionConsent?.TrySetException(new AAuthInteractionDeniedException(entry.DenyReason ?? "Mission consent denied."));
                    if (!entry.MissionResolved)
                    {
                        await AppendMissionTokenDenialAsync(missionLog, s256, entry.ResourceUrl, entry.Scope, entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                        entry.MissionResolved = true;
                    }
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);

                case PersonPendingStatus.Pending:
                default:
                    var (decision, _) = await ReviewMissionAsync(new MissionTokenConsentContext
                    {
                        AgentId = entry.AgentId,
                        ConsentAgentId = entry.ConsentAgentId,
                        UpstreamAuthorization = entry.UpstreamAuthorization,
                        ResourceUrl = entry.ResourceUrl,
                        Account = entry.Account,
                        AgentKeyThumbprint = entry.ResourceKeyThumbprint,
                        Scope = entry.Scope,
                        MissionS256 = s256,
                        Stage = MissionTokenConsentStage.Resolve,
                        Prompt = entry.Prompt,
                        Capabilities = entry.Capabilities,
                        AgentAsserted = entry.AgentAsserted,
                        ClarificationHistory = entry.ClarificationAnswers,
                        ResourceContext = entry.ResourceContext,
                    });
                    switch (decision.Kind)
                    {
                        case MissionTokenConsentKind.Grant:
                            return await ResolveMissionGrantAsync(entry);
                        case MissionTokenConsentKind.Deny:
                            await AppendMissionTokenDenialAsync(missionLog, s256, entry.ResourceUrl, entry.Scope, entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                            entry.MissionResolved = true;
                            entry.Status = PersonPendingStatus.Denied;
                            entry.DenyReason = decision.Reason ?? "the user denied this request";
                            entry.FederationMissionConsent?.TrySetException(new AAuthInteractionDeniedException(entry.DenyReason));
                            ctx.Response.Headers["Cache-Control"] = "no-store";
                            return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);
                        case MissionTokenConsentKind.Clarify:
                            if (entry.ClarificationRounds >= ClarificationExchange.DefaultMaxRounds)
                                return AAuthProblemDetails.Create("denied", "Clarification round limit reached.", statusCode: 403);
                            entry.Status = PersonPendingStatus.AwaitingClarification;
                            entry.ClarificationQuestion = decision.Question;
                            entry.ClarificationTimeout = decision.Timeout;
                            entry.ClarificationOptions = decision.Options;
                            return Pending202Clarification(ctx, entry, options);
                        case MissionTokenConsentKind.Interact:
                        default:
                            return Pending202(ctx, entry, options, interactionUrl);
                    }
            }
        }

        async Task<IResult> MintMissionEntryAsync(PersonPendingEntry entry)
        {
            if (entry.FederationMissionConsent is { } approval)
            {
                entry.MissionGate = false;
                entry.Status = PersonPendingStatus.Pending;
                approval.TrySetResult(true);
                return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }
            var response = await MintEntry(entry);
            if (!entry.MissionResolved && response is IStatusCodeHttpResult { StatusCode: StatusCodes.Status200OK })
            {
                await AppendMissionTokenAsync(app.Services.GetRequiredService<IMissionLog>(), entry.MissionS256!,
                    entry.ResourceUrl, entry.Scope, "OutOfScope", entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                entry.MissionResolved = true;
            }
            return response;
        }

        // Mint an out-of-scope grant: the asserter decides consent and releases
        // identity claims; the verdict is cached on the entry so a repeat poll is idempotent.
        async Task<IResult> ResolveMissionGrantAsync(PersonPendingEntry entry)
        {
            if (entry.FederationMissionConsent is not null)
                return await MintMissionEntryAsync(entry);
            var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                ResourceUrl = entry.ResourceUrl,
                Account = entry.Account,
                AgentKeyThumbprint = entry.ResourceKeyThumbprint,
                Scope = entry.Scope,
                AgentId = entry.ConsentAgentId,
                Subject = entry.PersonSubject,
                MissionS256 = entry.MissionS256,
                Prompt = entry.Prompt,
                Capabilities = entry.Capabilities,
                AgentAsserted = entry.AgentAsserted,
                ResourceContext = entry.ResourceContext,
                UpstreamAuthorization = entry.UpstreamAuthorization,
            });
            if (asserted.Kind != IdentityAssertionKind.Assert)
            {
                entry.Status = PersonPendingStatus.Denied;
                entry.DenyReason = asserted.Reason ?? "identity assertion failed";
                return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);
            }
            entry.Roles = asserted.Roles;
            entry.Groups = asserted.Groups;
            entry.AdditionalClaims = asserted.AdditionalClaims;
            entry.Status = PersonPendingStatus.Allowed;
            return await MintMissionEntryAsync(entry);
        }

        // ---- three-party (PS-issued) handler --------------------------------
        async Task<IResult> HandleThreePartyAsync(
            HttpContext ctx, AgentIssuanceContext issuance, string resourceTokenJwt, string presentedTokenJwt,
            string? prompt = null, IReadOnlyList<string>? capabilities = null, AgentAssertedContent? agentAsserted = null,
            PersonPendingEntry? resumed = null)
        {
            TokenVerifier.VerifiedToken resource, presented;
            try
            {
                (resource, presented) = await VerifyPairAsync(resourceTokenJwt, presentedTokenJwt, issuer,
                    issuance.ConfirmationKey.ComputeJwkThumbprint(), ctx.RequestAborted);
                issuance.ValidateResourceContext(resource.Payload);
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.TokenFailure(ex, TokenCredential.Resource);
            }

            // `iss` becomes the auth token's `aud`; `sub`, `tenant` and `mission_s256`
            // are copied from the resource token (verified equal to the presented token's).
            var audience = resource.Issuer;
            var resourceContext = (JsonObject)resource.Payload.DeepClone();
            var account = resource.Account;
            var subject = resource.Subject!;
            var tenant = resource.Tenant;
            var missionS256 = resource.MissionS256;
            var requestedScope = (string?)resource.Payload["scope"] is { } scopeClaim && !string.IsNullOrWhiteSpace(scopeClaim)
                ? scopeClaim : options.DefaultScope;
            var ceiling = Earliest(issuance.ExpiresAt, presented.ExpiresAt);
            if (missionS256 is not null)
            {
                try
                {
                    if ((await ValidateMissionAsync(missionS256, issuance.AgentId, issuance.Upstream)).ExpiresAt is { } missionExpiry)
                        ceiling = Earliest(ceiling, missionExpiry);
                }
                catch (AAuthTokenExchangeException ex)
                { return ExchangeFailure(ex.ErrorCode, ex.Detail, ex.StatusCode); }
            }

            var (registered, sourceFailure) = await RegisterSourcesAsync(issuance, presented, missionS256, ctx.RequestAborted);
            if (sourceFailure is not null) return sourceFailure;
            var sourceTokens = registered!;

            PersonPendingEntry Park()
            {
                var entry = resumed ?? pending.Add(audience, requestedScope, issuance.AgentId, issuance.ConfirmationKey,
                    issuance.AgentTokenExpiresAt, missionS256, ceiling);
                BindOwner(ctx, entry);
                BindResource(entry, resourceTokenJwt, issuer, issuance.ConfirmationKey);
                entry.PresentedToken = presentedTokenJwt;
                entry.PersonSubject = subject;
                entry.PersonTenant = tenant;
                entry.SourceTokens = Keys(sourceTokens);
                entry.UpstreamAuthorization = issuance.Upstream;
                entry.Prompt = prompt;
                entry.Capabilities = capabilities;
                entry.AgentAsserted = agentAsserted;
                return entry;
            }

            // §Resource-Initiated Interaction: resolve the resource's flow first.
            if (resumed is null && resourceContext.ContainsKey("interaction"))
            {
                PersonResourceInteraction? resourceInteraction;
                try { resourceInteraction = await PersonResourceInteraction.CreateAsync(resourceContext, resourceTokenJwt, options.EgressPolicy, ctx.RequestAborted); }
                catch (TokenVerificationException) { return AAuthProblemDetails.Create("invalid_resource_token", statusCode: 400); }
                var resourceEntry = Park();
                resourceEntry.ResourceInteraction = resourceInteraction;
                resourceEntry.InteractionUrl = interactionUrl + "/resource";
                resourceEntry.ResumeAuthorization = active => HandleThreePartyAsync(active, issuance,
                    resourceEntry.ResourceToken!, resourceEntry.PresentedToken!, prompt, capabilities, agentAsserted, resourceEntry);
                return Pending202(ctx, resourceEntry, options, interactionUrl);
            }

            var agentKeyThumbprint = issuance.ConfirmationKey.ComputeJwkThumbprint();
            if (missionS256 is not null)
            {
                var missionLog = app.Services.GetRequiredService<IMissionLog>();

                // Gate 2a/2c: the consent seam decides in-scope-silent vs the
                // out-of-scope review (grant / deny / clarify / interactive hold).
                MissionTokenConsentDecision decision;
                string consentDetail;
                try
                {
                    (decision, consentDetail) = await ReviewMissionAsync(new MissionTokenConsentContext
                    {
                        AgentId = issuance.AgentId,
                        ConsentAgentId = issuance.AgentId,
                        UpstreamAuthorization = issuance.Upstream,
                        ResourceContext = resourceContext,
                        ResourceUrl = audience,
                        Account = account,
                        AgentKeyThumbprint = agentKeyThumbprint,
                        Scope = requestedScope,
                        MissionS256 = missionS256,
                        Stage = MissionTokenConsentStage.Gate,
                        Prompt = prompt,
                        Capabilities = capabilities,
                        AgentAsserted = agentAsserted,
                    });
                }
                catch (AAuthTokenExchangeException ex)
                {
                    return ExchangeFailure(ex.ErrorCode, ex.Detail, ex.StatusCode);
                }
                switch (decision.Kind)
                {
                    case MissionTokenConsentKind.Grant:
                        // Gate 2a: within the approved intent → silent grant.
                        var granted = await asserter.AssertAsync(new IdentityAssertionRequest
                        {
                            ResourceUrl = audience,
                            Account = account,
                            AgentKeyThumbprint = agentKeyThumbprint,
                            Scope = requestedScope,
                            AgentId = issuance.AgentId,
                            Subject = subject,
                            MissionS256 = missionS256,
                            LoginHint = (string?)resourceContext["login_hint"],
                            Prompt = prompt,
                            Capabilities = capabilities,
                            AgentAsserted = agentAsserted,
                            ResourceContext = resourceContext,
                            UpstreamAuthorization = issuance.Upstream,
                        });
                        if (granted.Kind != IdentityAssertionKind.Assert)
                            return AAuthProblemDetails.Create("denied", granted.Reason, statusCode: StatusCodes.Status403Forbidden);
                        var response = await AuthTokenResponse.CreateTrackedAsync(ct => MintAuth(ct,
                            audience, requestedScope, issuance.ConfirmationKey, subject, tenant, granted.Roles,
                            granted.Groups, granted.AdditionalClaims, missionS256,
                            issuance.AgentTokenExpiresAt, ceiling, account), ceiling, inventory, sourceTokens, "auth_token",
                            options.TimeProvider, ceilingExpired: MissionExpired(missionS256));
                        if (response is IStatusCodeHttpResult { StatusCode: StatusCodes.Status200OK })
                            await AppendMissionTokenAsync(missionLog, missionS256, audience, requestedScope, consentDetail,
                                account, issuance.AgentId, agentKeyThumbprint);
                        return response;
                    case MissionTokenConsentKind.Deny:
                        await AppendMissionTokenDenialAsync(missionLog, missionS256, audience, requestedScope, account, issuance.AgentId, agentKeyThumbprint);
                        return AAuth.Server.AAuthProblemDetails.Create("denied", decision.Reason, statusCode: StatusCodes.Status403Forbidden);
                    case MissionTokenConsentKind.Clarify:
                        var clarifyEntry = Park();
                        clarifyEntry.MissionGate = true;
                        clarifyEntry.Status = PersonPendingStatus.AwaitingClarification;
                        clarifyEntry.ClarificationQuestion = decision.Question;
                        clarifyEntry.ClarificationTimeout = decision.Timeout;
                        clarifyEntry.ClarificationOptions = decision.Options;
                        return Pending202Clarification(ctx, clarifyEntry, options);
                    case MissionTokenConsentKind.Interact:
                    default:
                        var interactEntry = Park();
                        interactEntry.MissionGate = true;
                        return Pending202(ctx, interactEntry, options, interactionUrl);
                }
            }

            // Non-mission three-party path.
            var assertion = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                ResourceUrl = audience,
                Account = account,
                AgentKeyThumbprint = agentKeyThumbprint,
                Scope = requestedScope,
                AgentId = issuance.AgentId,
                Subject = subject,
                LoginHint = (string?)resourceContext["login_hint"],
                Prompt = prompt,
                Capabilities = capabilities,
                AgentAsserted = agentAsserted,
                UpstreamAuthorization = issuance.Upstream,
                ResourceContext = resourceContext,
            });
            switch (assertion.Kind)
            {
                case IdentityAssertionKind.Assert:
                    return await AuthTokenResponse.CreateTrackedAsync(ct => MintAuth(ct,
                        audience, requestedScope, issuance.ConfirmationKey, subject, tenant, assertion.Roles,
                        assertion.Groups, assertion.AdditionalClaims, missionS256: null,
                        issuance.AgentTokenExpiresAt, ceiling, account), ceiling, inventory, sourceTokens, "auth_token",
                        options.TimeProvider, ctx.RequestAborted);
                case IdentityAssertionKind.Deny:
                    return AAuth.Server.AAuthProblemDetails.Create("denied", assertion.Reason, statusCode: StatusCodes.Status403Forbidden);
                case IdentityAssertionKind.NeedsConsent:
                default:
                    return Pending202(ctx, Park(), options, interactionUrl);
            }
        }

        // ---- four-party (federated) handler --------------------------------
        async Task<IResult> HandleFederatedAsync(
            HttpContext ctx, AgentIssuanceContext issuance, string resourceTokenJwt, string presentedTokenJwt,
            JsonObject body, string resourceAudience, string? prompt, IReadOnlyList<string>? capabilities,
            AgentAssertedContent? agentAsserted)
        {
            // §PS-AS Trust Establishment: trust may be pre-established OR established
            // dynamically — "no separate registration step". Default open: federate to
            // the AS named in the (verified) resource-token aud. An empty
            // Trust.AccessServers allow-list disables four-party; a non-empty list
            // and/or predicate restricts.
            if (!AAuthUrl.IsHttpsOrLoopback(resourceAudience, options.EgressPolicy))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_access_server", $"Access Server audience '{resourceAudience}' must be an absolute https URL (loopback http allowed for development).", statusCode: StatusCodes.Status400BadRequest);
            }
            if (!await options.Trust.IsTrustedAsync(resourceAudience, AAuthTrustedParty.AccessServer,
                    ctx.RequestServices, ctx, cancellationToken: ctx.RequestAborted).ConfigureAwait(false))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_access_server", $"'{resourceAudience}' is not a trusted Access Server.", statusCode: StatusCodes.Status403Forbidden);
            }

            TokenVerifier.VerifiedToken resource, presented;
            try
            {
                (resource, presented) = await VerifyPairAsync(resourceTokenJwt, presentedTokenJwt, resourceAudience,
                    issuance.ConfirmationKey.ComputeJwkThumbprint(), ctx.RequestAborted);
                issuance.ValidateResourceContext(resource.Payload);
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.TokenFailure(ex, TokenCredential.Resource);
            }
            var resourceUrl = resource.Issuer;
            var federatedContext = (JsonObject)resource.Payload.DeepClone();
            var federatedMission = resource.MissionS256;
            var federatedScope = (string?)resource.Payload["scope"] is { } scopeClaim && !string.IsNullOrWhiteSpace(scopeClaim)
                ? scopeClaim : options.DefaultScope;
            var ceiling = Earliest(issuance.ExpiresAt, presented.ExpiresAt);

            if (federatedMission is not null)
            {
                try
                {
                    if ((await ValidateMissionAsync(federatedMission, issuance.AgentId, issuance.Upstream)).ExpiresAt is { } missionExpiry)
                        ceiling = Earliest(ceiling, missionExpiry);
                }
                catch (AAuthTokenExchangeException ex)
                { return ExchangeFailure(ex.ErrorCode, ex.Detail, ex.StatusCode); }
            }
            var (registered, sourceFailure) = await RegisterSourcesAsync(issuance, presented, federatedMission, ctx.RequestAborted);
            if (sourceFailure is not null) return sourceFailure;
            var sourceTokens = registered!;

            var federation = AAuthSeams.Resolve<AccessServerClient>(app.Services, name, null, () =>
                throw new InvalidOperationException("Four-party federation requires AddAAuthPersonServer(...).WithFederation()."));
            var entry = pending.Add(resourceUrl, federatedScope, issuance.AgentId, agentConfirmationKey: null,
                issuance.AgentTokenExpiresAt, federatedMission, ceiling);
            entry.ResourceContext = federatedContext;
            entry.UpstreamAuthorization = issuance.Upstream;
            entry.SourceTokens = Keys(sourceTokens);
            entry.Prompt = prompt;
            entry.Capabilities = capabilities;
            entry.AgentAsserted = agentAsserted;
            entry.PresentedToken = presentedTokenJwt;
            entry.PersonSubject = resource.Subject;
            entry.PersonTenant = resource.Tenant;
            BindOwner(ctx, entry);
            BindResource(entry, resourceTokenJwt, resourceAudience, issuance.ConfirmationKey);
            try { entry.ResourceInteraction = await PersonResourceInteraction.CreateAsync(federatedContext, resourceTokenJwt, options.EgressPolicy, ctx.RequestAborted); }
            catch (TokenVerificationException) { return AAuthProblemDetails.Create("invalid_resource_token", statusCode: 400); }
            if (entry.AwaitingResourceInteraction)
            {
                entry.InteractionUrl = interactionUrl + "/resource";
                entry.FirstAnswer.TrySetResult();
            }

            async Task ThrowIfMissionTerminatedAsync()
            {
                if (entry.MissionS256 is { } current
                    && await app.Services.GetRequiredService<IMissionStore>().GetAsync(current) is { State: MissionState.Terminated })
                    throw new AAuthTokenExchangeException("mission_terminated", null, 403, true);
            }

            string? consentedResourceToken = null;
            string? missionConsentedResourceToken = null;
            async Task<IdentityAssertion> RequireConsentAsync(IReadOnlyList<string>? requiredClaims, System.Threading.CancellationToken ct)
            {
                if (entry.ResourceInteraction is { } resourceInteraction
                    && !await resourceInteraction.Completion.Task.WaitAsync(ct))
                    throw new AAuthTokenExchangeException(resourceInteraction.Error!, null, resourceInteraction.ErrorStatus, true);
                await ThrowIfMissionTerminatedAsync();
                if (entry.MissionS256 is { } mission && missionConsentedResourceToken != entry.ResourceToken)
                {
                    var (decision, _) = await ReviewMissionAsync(new MissionTokenConsentContext
                    {
                        AgentId = entry.AgentId, ResourceUrl = entry.ResourceUrl, Account = entry.Account,
                        ConsentAgentId = entry.ConsentAgentId, UpstreamAuthorization = entry.UpstreamAuthorization,
                        AgentKeyThumbprint = entry.ResourceKeyThumbprint, Scope = entry.Scope, MissionS256 = mission,
                        Stage = MissionTokenConsentStage.Gate, Prompt = entry.Prompt, Capabilities = entry.Capabilities,
                        AgentAsserted = entry.AgentAsserted,
                        ResourceContext = entry.ResourceContext, ClarificationHistory = entry.ClarificationAnswers,
                    });
                    if (decision.Kind == MissionTokenConsentKind.Deny)
                    {
                        await AppendMissionTokenDenialAsync(app.Services.GetRequiredService<IMissionLog>(), mission,
                            entry.ResourceUrl, entry.Scope, entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                        throw new AAuthInteractionDeniedException(decision.Reason ?? "Mission consent denied.");
                    }
                    if (decision.Kind is MissionTokenConsentKind.Clarify or MissionTokenConsentKind.Interact)
                    {
                        Task approval;
                        await entry.Lifecycle.Gate.WaitAsync(ct);
                        try
                        {
                            entry.MissionGate = true;
                            entry.FederationMissionConsent = new(TaskCreationOptions.RunContinuationsAsynchronously);
                            entry.Status = decision.Kind == MissionTokenConsentKind.Clarify
                                ? PersonPendingStatus.AwaitingClarification : PersonPendingStatus.Pending;
                            entry.ClarificationQuestion = decision.Question;
                            entry.ClarificationTimeout = decision.Timeout;
                            entry.ClarificationOptions = decision.Options;
                            entry.Browser.Renew();
                            approval = entry.FederationMissionConsent.Task;
                            entry.FirstAnswer.TrySetResult();
                        }
                        finally { entry.Lifecycle.Gate.Release(); }
                        await approval.WaitAsync(ct);
                        await ThrowIfMissionTerminatedAsync();
                    }
                    missionConsentedResourceToken = entry.ResourceToken;
                }
                entry.RequiredIdentityClaims = requiredClaims;
                var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
                {
                    ResourceUrl = resourceUrl,
                    Account = entry.Account,
                    AgentKeyThumbprint = entry.ResourceKeyThumbprint,
                    Scope = entry.Scope,
                    AgentId = issuance.AgentId,
                    Subject = entry.PersonSubject,
                    RequiredClaims = requiredClaims,
                    MissionS256 = entry.MissionS256,
                    LoginHint = (string?)entry.ResourceContext?["login_hint"],
                    Prompt = entry.Prompt,
                    Capabilities = entry.Capabilities,
                    AgentAsserted = entry.AgentAsserted,
                    ResourceContext = entry.ResourceContext,
                    InteractionId = entry.Id,
                    UpstreamAuthorization = issuance.Upstream,
                }, ct);
                if (asserted.Kind == IdentityAssertionKind.NeedsConsent)
                {
                    Task<IdentityAssertion> approval;
                    await entry.Lifecycle.Gate.WaitAsync(ct);
                    try
                    {
                        ct.ThrowIfCancellationRequested();
                        entry.FederationConsent = new(TaskCreationOptions.RunContinuationsAsynchronously);
                        entry.Status = PersonPendingStatus.Pending;
                        entry.InteractionUrl = null;
                        entry.InteractionCode = null;
                        entry.Browser.Renew();
                        approval = entry.FederationConsent.Task;
                        entry.FirstAnswer.TrySetResult();
                    }
                    finally { entry.Lifecycle.Gate.Release(); }
                    asserted = await approval.WaitAsync(ct);
                }
                if (asserted.Kind != IdentityAssertionKind.Assert)
                    throw new AAuthInteractionDeniedException(asserted.Reason ?? "PS consent was not asserted.");
                await ThrowIfMissionTerminatedAsync();
                consentedResourceToken = entry.ResourceToken;
                return asserted;
            }

            // Replace the pending request with a verified updated_request pair: same
            // iss, ps, sub, agent_jkt, mission_s256 and tenant as the original.
            AccessServerRequest fedRequest = null!;
            async Task ApplyReplacementAsync(string replacementResourceToken, string replacementPresentedToken,
                System.Threading.CancellationToken ct)
            {
                var (replacement, replacementPresented) = await VerifyPairAsync(replacementResourceToken, replacementPresentedToken,
                    resourceAudience, entry.ResourceKeyThumbprint!, ct);
                RequireSameRequest(entry.ResourceContext!, replacement.Payload);
                if (!AccountBinding.Matches(entry.Account, replacement.Account))
                    throw new TokenVerificationException("Changing account requires a new authorization request.");
                var replacementInteraction = await PersonResourceInteraction.CreateAsync(replacement.Payload,
                    replacementResourceToken, options.EgressPolicy, ct);
                entry.Scope = (string?)replacement.Payload["scope"] ?? options.DefaultScope;
                entry.ResourceToken = replacementResourceToken;
                entry.PresentedToken = replacementPresentedToken;
                entry.ResourceContext = (JsonObject)replacement.Payload.DeepClone();
                entry.ResourceInteraction = replacementInteraction;
                if (replacementInteraction is not null) entry.InteractionUrl = interactionUrl + "/resource";
                fedRequest.PresentedTokenExpiresAt = replacementPresented.ExpiresAt;
            }

            var agentTokenJwt = ctx.GetAAuthParsedKey()?.Jwt
                ?? throw new InvalidOperationException("Agent token JWT unavailable on the verified request.");
            fedRequest = new AccessServerRequest
            {
                ResourceToken = resourceTokenJwt,
                AgentToken = agentTokenJwt,
                PresentedToken = presentedTokenJwt,
                PresentedTokenExpiresAt = presented.ExpiresAt,
                SubagentToken = StringMember(body, "subagent_token"),
                AuthorizationExpiresAt = ceiling,
                UpstreamToken = StringMember(body, "upstream_token"),
                ExpectedAudience = resourceUrl,
                ExpectedSubject = resource.Subject!,
                ExpectedPersonServer = issuer,
                AgentKey = issuance.ConfirmationKey,
                ExpectedMissionS256 = federatedMission,
                Account = entry.Account,
                RequestedScope = federatedScope,
                OnClarificationRequired = async (question, ct) =>
                {
                    var localAnswer = options.TriageClarificationAsync is { } triage
                        ? await triage(entry, question, ct) : null;
                    if (localAnswer is not null)
                    {
                        if (localAnswer.Action == ClarificationResponse.Kind.Update)
                        {
                            await ApplyReplacementAsync(localAnswer.ResourceToken!, localAnswer.PresentedToken!, ct);
                            fedRequest.RequestedScope = entry.Scope;
                        }
                        if (entry.ResourceToken != consentedResourceToken) await RequireConsentAsync(null, ct);
                        return localAnswer;
                    }
                    Task<ClarificationResponse> answer;
                    await entry.Lifecycle.Gate.WaitAsync(ct);
                    try
                    {
                        ct.ThrowIfCancellationRequested();
                        entry.FederationAnswer = new(TaskCreationOptions.RunContinuationsAsynchronously);
                        entry.Status = PersonPendingStatus.AwaitingClarification;
                        entry.ClarificationQuestion = question.Clarification;
                        entry.ClarificationTimeout = question.TimeoutSeconds;
                        entry.ClarificationOptions = question.Options;
                        entry.ClarificationDeadline = options.TimeProvider.GetUtcNow().AddSeconds(question.TimeoutSeconds ?? 300);
                        answer = entry.FederationAnswer.Task;
                        entry.FirstAnswer.TrySetResult();
                    }
                    finally { entry.Lifecycle.Gate.Release(); }
                    var result = await answer.WaitAsync(ct);
                    if (result.Action == ClarificationResponse.Kind.Update && result.PresentedToken is { } updatedPresented)
                        fedRequest.PresentedTokenExpiresAt = DateTimeOffset.FromUnixTimeSeconds(
                            (long)TokenVerifier.DecodeJsonSegment(updatedPresented.Split('.')[1], "payload")["exp"]!);
                    fedRequest.RequestedScope = entry.Scope;
                    if (entry.ResourceToken != consentedResourceToken) await RequireConsentAsync(null, ct);
                    return result;
                },
                OnInteractionRequired = (interaction, _) =>
                {
                    entry.InteractionUrl = interaction.Url;
                    entry.InteractionCode = interaction.Code;
                    entry.FirstAnswer.TrySetResult();
                    return Task.CompletedTask;
                },
                // The AS needs identity claims (§Claims Required) beyond the presented
                // token's identity. The PS is the identity authority — answer via the
                // same asserter, projecting only the requested claims (never `sub`).
                OnClaimsRequired = async (claimsRequirement, ct) =>
                {
                    var asserted = await RequireConsentAsync(claimsRequirement.RequiredClaims, ct);
                    return new ClaimsResponse { Claims = ProjectClaims(asserted, claimsRequirement.RequiredClaims) };
                },
            };

            _ = Task.Run(async () =>
            {
                try
                {
                    entry.FederationCancellation.CancelAfter(entry.PendingExpiresAt - options.TimeProvider.GetUtcNow());
                    await RequireConsentAsync(null, entry.FederationCancellation.Token);
                    var token = await federation.FederateAsync(resourceAudience, fedRequest, entry.FederationCancellation.Token);
                    await ThrowIfMissionTerminatedAsync();
                    var tracked = await AuthTokenResponse.CreateTrackedAsync(_ => ValueTask.FromResult(token), entry.ExpiresAt,
                        inventory, entry.SourceTokens, options.TimeProvider, entry.FederationCancellation.Token);
                    if (tracked is not IStatusCodeHttpResult { StatusCode: StatusCodes.Status200OK })
                        throw new AAuthInteractionDeniedException("Source authorization was revoked before federation completed.");
                    if (entry.MissionS256 is { } grantedMission)
                        await AppendMissionTokenAsync(app.Services.GetRequiredService<IMissionLog>(), grantedMission,
                            entry.ResourceUrl, entry.Scope, "Federated", entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                    await entry.Lifecycle.Gate.WaitAsync();
                    try
                    {
                        if (!entry.Lifecycle.Cancelled && !entry.Lifecycle.Delivered
                            && entry.Status != PersonPendingStatus.Denied && !entry.AwaitingFederationConsent
                            && consentedResourceToken == entry.ResourceToken)
                        {
                            entry.AuthToken = token;
                            entry.Status = PersonPendingStatus.Allowed;
                        }
                    }
                    finally { entry.Lifecycle.Gate.Release(); }
                }
                // Only the PS's own cancellation (agent DELETE or pending expiry) is
                // `expired`; an AS call that times out is an unreachable AS.
                catch (Exception ex) when (ex is AAuthClarificationCancelledException
                    || ex is OperationCanceledException && entry.FederationCancellation.IsCancellationRequested)
                {
                    entry.Error = "expired";
                    entry.ErrorStatus = StatusCodes.Status408RequestTimeout;
                    entry.Status = PersonPendingStatus.Denied;
                }
                catch (AAuthInteractionDeniedException)
                {
                    entry.Error = "denied";
                    entry.ErrorStatus = StatusCodes.Status403Forbidden;
                    entry.Status = PersonPendingStatus.Denied;
                }
                catch (AAuthTokenExchangeException ex)
                {
                    entry.Error = ex.ErrorCode;
                    entry.ErrorStatus = ex.StatusCode;
                    entry.Status = PersonPendingStatus.Denied;
                }
                catch (AAuthPaymentRequiredException ex)
                {
                    entry.Error = "payment_required";
                    entry.ErrorStatus = StatusCodes.Status402PaymentRequired;
                    entry.ErrorLocation = ex.Location;
                    entry.Status = PersonPendingStatus.Denied;
                }
                catch (Exception ex)
                {
                    // §Auth Token Delivery: no verifiable auth token from the AS.
                    entry.Error = "as_unreachable";
                    entry.ErrorStatus = StatusCodes.Status502BadGateway;
                    logger.LogWarning("Four-party federation failed. Status={StatusCode}; Error={ErrorCode}.",
                        ex is System.Net.Http.HttpRequestException requestError ? (int?)requestError.StatusCode : null,
                        "as_unreachable");
                    entry.Status = PersonPendingStatus.Denied;
                }
                finally
                {
                    entry.FirstAnswer.TrySetResult();
                }
            });

            await entry.FirstAnswer.Task;

            if (entry.AwaitingResourceInteraction)
                return Pending202(ctx, entry, options, interactionUrl);

            if (entry.MissionGate && entry.Status != PersonPendingStatus.AwaitingClarification)
                return Pending202(ctx, entry, options, interactionUrl);
            if (entry.AwaitingFederationConsent)
                return Pending202(ctx, entry, options, interactionUrl);

            if (entry.Status == PersonPendingStatus.AwaitingClarification)
                return Pending202Clarification(ctx, entry, options);

            if (entry.InteractionUrl is not null)
            {
                ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                ctx.Response.Headers["Retry-After"] = "1";
                ctx.Response.Headers["Cache-Control"] = "no-store";
                ctx.Response.Headers[AAuthRequirementHeader.Name] =
                    Interaction.Format(entry.InteractionUrl, entry.InteractionCode!, options.EgressPolicy);
                return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }

            if (entry.Status == PersonPendingStatus.Allowed)
            {
                return await AuthTokenResponse.CreateTrackedAsync(_ => ValueTask.FromResult(entry.AuthToken!), entry.ExpiresAt,
                    inventory, entry.SourceTokens, options.TimeProvider, ctx.RequestAborted);
            }

            if (!string.IsNullOrEmpty(entry.ErrorLocation))
            {
                ctx.Response.Headers.Location = entry.ErrorLocation;
            }
            return ExchangeFailure(entry.Error ?? "denied", null, entry.ErrorStatus ?? StatusCodes.Status403Forbidden);
        }
    }

    private static void RequireSameRequest(JsonObject original, JsonObject replacement)
        => TokenVerifier.RequireSameResourceRequest(original, replacement);

    private static IResult PendingWithoutRequirement(HttpContext ctx, PersonPendingEntry entry, AAuthPersonServerOptions options)
    {
        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    private static IResult Pending202(
        HttpContext ctx, PersonPendingEntry entry, AAuthPersonServerOptions options, string interactionUrl)
    {
        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
        // Human-consent wait: poll at ~1s (a browser approval takes seconds), not the
        // 100ms MinPollInterval floor a `Retry-After: 0` would clamp to. Matches the
        // four-party interaction path and the AS/Concierge/R3 endpoints.
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] = Interaction.Format(
            entry.InteractionUrl ?? interactionUrl, entry.InteractionCode ?? entry.Browser.Code, options.EgressPolicy);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // True when the verified carrier on this request is the agent that parked the
    // entry — guards the clarification POST/DELETE so one agent cannot answer or
    // withdraw another's pending request (the signature is already verified).
    private static bool RequesterMatches(HttpContext ctx, PersonPendingEntry entry)
    {
        var parsed = ctx.GetAAuthParsedKey();
        return ctx.GetAAuthTokenType() == AAuthTokenType.AgentToken
            && entry.OwnerIssuer is not null && entry.OwnerSubject is not null
            && entry.OwnerKeyThumbprint is not null
            && string.Equals((string?)parsed?.Payload?["iss"], entry.OwnerIssuer, StringComparison.Ordinal)
            && string.Equals((string?)parsed?.Payload?["sub"], entry.OwnerSubject, StringComparison.Ordinal)
            && string.Equals(parsed?.ConfirmationKey?.ComputeJwkThumbprint(), entry.OwnerKeyThumbprint, StringComparison.Ordinal);
    }

    private static void BindOwner(HttpContext ctx, PersonPendingEntry entry)
    {
        var parsed = ctx.GetAAuthParsedKey()!;
        entry.OwnerIssuer = (string?)parsed.Payload?["iss"];
        entry.OwnerSubject = (string?)parsed.Payload?["sub"];
        entry.OwnerKeyThumbprint = parsed.ConfirmationKey!.ComputeJwkThumbprint();
    }

    private static void BindResource(PersonPendingEntry entry, string resourceToken, string audience, IAAuthKey key)
    {
        entry.ResourceContext = TokenVerifier.DecodeJsonSegment(resourceToken.Split('.')[1], "payload");
        entry.ResourceToken = resourceToken;
        entry.ResourceAudience = audience;
        entry.ResourceKeyThumbprint = key.ComputeJwkThumbprint();
    }

    private static string? StringMember(JsonObject? body, string name) =>
        body?[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    // §Consent Presentation: justification, platform and device are agent-asserted.
    // Each is optional; a present member that is not a string is malformed.
    private static bool TryReadAgentAsserted(JsonObject? body, out AgentAssertedContent? content)
    {
        content = null;
        string?[] values = [StringMember(body, "justification"), StringMember(body, "platform"), StringMember(body, "device")];
        if ((body?.ContainsKey("justification") == true && values[0] is null)
            || (body?.ContainsKey("platform") == true && values[1] is null)
            || (body?.ContainsKey("device") == true && values[2] is null))
            return false;
        if (values.Any(value => value is not null))
            content = new AgentAssertedContent { Justification = values[0], Platform = values[1], Device = values[2] };
        return true;
    }

    // The §requirement-clarification 202: emit the AAuth-Requirement header and a
    // body carrying the question (plus optional timeout/options).
    private static IResult Pending202Clarification(
        HttpContext ctx, PersonPendingEntry entry, AAuthPersonServerOptions options)
    {
        entry.ClarificationDeadline ??= options.TimeProvider.GetUtcNow().AddSeconds(entry.ClarificationTimeout ?? 300);
        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
        ctx.Response.Headers["Retry-After"] = "0";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            $"requirement={ClarificationRequirement.RequirementType}";
        var body = new JsonObject
        {
            ["status"] = "pending",
            ["clarification"] = entry.ClarificationQuestion,
        };
        if (entry.ClarificationTimeout is int timeout)
        {
            body["timeout"] = timeout;
        }
        if (entry.ClarificationOptions is { Count: > 0 } opts)
        {
            var array = new JsonArray();
            foreach (var option in opts)
            {
                array.Add(option);
            }
            body["options"] = array;
        }
        return Results.Json(body, statusCode: StatusCodes.Status202Accepted);
    }

    private static Task AppendMissionTokenDenialAsync(
        IMissionLog missionLog, string s256, string resource, string scope,
        string? account, string? agentId, string? agentKeyThumbprint)
        => missionLog.AppendAsync(new MissionLogEntry(s256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = resource,
            Scope = scope,
            Granted = false,
            Account = account,
            AgentId = agentId,
            AgentKeyThumbprint = agentKeyThumbprint,
            Detail = "OutOfScope",
        });

    private static Task AppendMissionTokenAsync(
        IMissionLog missionLog, string s256, string resource, string scope, string detail,
        string? account, string? agentId, string? agentKeyThumbprint)
        => missionLog.AppendAsync(new MissionLogEntry(s256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = resource,
            Scope = scope,
            Granted = true,
            Account = account,
            AgentId = agentId,
            AgentKeyThumbprint = agentKeyThumbprint,
            Detail = detail,
        });

    // Project the asserter's claims (tenant/roles/groups/additional) into the
    // §Claims Required push payload, limited to the names the AS requested.
    private static IReadOnlyDictionary<string, JsonNode?> ProjectClaims(
        IdentityAssertion asserted, IReadOnlyList<string> requiredClaims)
    {
        var result = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        foreach (var name in requiredClaims)
        {
            switch (name)
            {
                case "tenant" when asserted.Tenant is not null:
                    result["tenant"] = asserted.Tenant;
                    break;
                case "roles" when asserted.Roles is not null:
                    result["roles"] = new JsonArray(System.Linq.Enumerable.ToArray(
                        System.Linq.Enumerable.Select(asserted.Roles, r => (JsonNode?)r)));
                    break;
                case "groups" when asserted.Groups is not null:
                    result["groups"] = new JsonArray(System.Linq.Enumerable.ToArray(
                        System.Linq.Enumerable.Select(asserted.Groups, g => (JsonNode?)g)));
                    break;
                default:
                    if (!AuthTokenBuilder.IsReservedClaim(name) && asserted.AdditionalClaims is not null
                        && asserted.AdditionalClaims.TryGetValue(name, out var value))
                    {
                        result[name] = value?.DeepClone();
                    }
                    break;
            }
        }
        return result;
    }

    // Peek the `aud` claim of a (possibly unverified) compact JWT without
    // checking its signature — used only to ROUTE the request (three- vs
    // four-party). Both branches fully verify the token afterwards.
    private static string? PeekJwtAudience(string jwt, TokenVerifier verifier) =>
        (string?)verifier.ReadStructure(jwt, ResourceTokenBuilder.TokenType).Payload["aud"];

    // Parse a JSON array of strings (e.g. the `capabilities` body parameter) into
    // a list, skipping non-string entries. Returns null when absent/empty so the
    // asserter can distinguish "not declared" from "declared empty".
    private static IReadOnlyList<string>? ParseStringArray(JsonArray? array)
    {
        if (array is null || array.Count == 0)
        {
            return null;
        }
        var list = new List<string>(array.Count);
        foreach (var node in array)
        {
            if (node is JsonValue v && v.TryGetValue<string>(out var s) && !string.IsNullOrEmpty(s))
            {
                list.Add(s);
            }
        }
        return list.Count > 0 ? list : null;
    }
}

using System.Collections.Concurrent;
using System.Net;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.R3.Model;
using AAuth.Server;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.R3;

/// <summary>Self-contained R3 Access Server metadata, JWKS, and token endpoint.</summary>
public static class R3AccessTokenEndpoint
{
    public static WebApplication MapR3AccessTokenEndpoint(this WebApplication app, R3AccessTokenEndpointOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        var (signingKid, signingKey) = options.FirstSigningKey();
        options.EgressPolicy.ValidateIdentifier(options.Issuer);
        var issuer = options.Issuer;
        var inventory = app.MapAAuthIssuerRevocation(issuer, AuthTokenBuilder.AccessDwk,
            signingKey, signingKid, "/revoke", options.EgressPolicy, options.TimeProvider, configure: null);
        var tokenPath = "/" + options.TokenPath.Trim('/');

        WellKnownEndpoints.MapAAuthAccessServerWellKnown(app, new AAuthAccessServerMetadataOptions
        {
            EgressPolicy = options.EgressPolicy,
            Issuer = issuer,
            AuthTokenEndpoint = $"{issuer}{tokenPath}",
            SigningKeys = options.SigningKeys,
            RevocationEndpoint = $"{issuer}/revoke",
        });

        var pendingPath = "/" + options.PendingPath.Trim('/');
        var consentPath = "/" + options.ConsentPath.Trim('/');
        var pendingStore = new R3PendingStore(options.TimeProvider);
        var browserConsent = options.BrowserConsent ?? new BrowserConsentSessions("AAuth.R3.Consent");

        // Mint the R3 auth token + write the audit record atomically. Shared by the
        // /token happy path (granted class docs) and the /pending poll after per-call
        // human consent (r3 §Per-Call Proposals, Flow step 2 + §Audit Log Integrity).
        async Task<string> MintAndAuditAsync(AuthMintParts parts, AgentIssuanceContext issuance, string resourceIssuer, CancellationToken ct)
        {
            var claims = R3AuthClaims.AuthToken(parts.Uri, parts.S256, parts.Granted, parts.Conditional, options.VocabularySchemas);
            var token = new AuthTokenBuilder
            {
                EgressPolicy = options.EgressPolicy,
                Issuer = issuer,
                Audience = resourceIssuer,
                Account = parts.Account,
                MissionS256 = parts.MissionS256,
                PersonServer = parts.PersonServer,
                AgentConfirmationKey = issuance.ConfirmationKey,
                AgentTokenExpiresAt = issuance.AgentTokenExpiresAt,
                AuthorizationExpiresAt = parts.ExpiresAt,
                TimeProvider = options.TimeProvider,
                Key = signingKey,
                KeyId = signingKid,
                Dwk = AuthTokenBuilder.AccessDwk,
                Subject = parts.Subject,
                Tenant = parts.Tenant,
                Scope = parts.Scope,
                AdditionalClaims = claims,
            }.Build();
            var payload = JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!;
            await options.AuditSink.RecordTokenIssuanceAsync(new R3TokenIssuanceAuditRecord(
                parts.Uri, parts.S256, issuance.AgentId, resourceIssuer, issuer,
                DateTimeOffset.FromUnixTimeSeconds((long)payload["iat"]!), parts.IssuanceKind)
            {
                Account = parts.Account,
                TokenId = (string)payload["jti"]!,
                TokenS256 = R3Hash.ComputeS256(System.Text.Encoding.ASCII.GetBytes(token)),
            }, ct);
            return token;
        }

        app.MapPost(tokenPath, async (HttpContext context) =>
        {
            R3VerifiedFetcher caller;
            try
            {
                caller = await R3DocumentEndpoint.VerifyFetcherAsync(context, options.IsCallerTrustedPersonServer);
            }
            catch (R3UntrustedJwksUriException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", statusCode: StatusCodes.Status403Forbidden);
            }
            catch (Exception ex) when (ex is R3FetchVerificationException or AAuth.HttpSig.AAuthVerificationException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_signature", ex.Message, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!options.IsCallerTrustedPersonServer(caller))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", statusCode: StatusCodes.Status403Forbidden);
            }

            var tokenVerifier = GetServiceOrDefault(context, new TokenVerifier { EgressPolicy = options.EgressPolicy });
            JsonObject? body;
            try
            {
                body = await TokenRequestBody.ReadAsync(context.Request, tokenVerifier);
            }
            catch (System.Text.Json.JsonException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "body is not valid JSON", statusCode: StatusCodes.Status400BadRequest);
            }
            catch (TokenVerificationException ex) { return AAuthProblemDetails.TokenFailure(ex); }

            var agentToken = (string?)body?["agent_token"];
            var resourceToken = (string?)body?["resource_token"];
            var presentedToken = (string?)body?["presented_token"];
            if (string.IsNullOrWhiteSpace(agentToken) || string.IsNullOrWhiteSpace(resourceToken) || string.IsNullOrWhiteSpace(presentedToken))
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing agent_token, resource_token or presented_token", statusCode: StatusCodes.Status400BadRequest);
            }

            var metadata = GetRequired<MetadataClient>(context);
            var jwks = GetRequired<JwksClient>(context);

            AgentIssuanceContext issuance;
            try
            {
                issuance = await AgentIssuanceContext.VerifyAsync(
                    agentToken, (string?)body?["subagent_token"], (string?)body?["upstream_token"], caller.Identifier,
                    tokenVerifier, metadata, jwks, static _ => true, context.RequestAborted);
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.TokenFailure(ex);
            }

            TokenVerifier.VerifiedToken verifiedResource;
            TokenVerifier.VerifiedToken verifiedPresented;
            R3ClaimReader.ResourceDocumentClaims r3DocumentClaims;
            try
            {
                verifiedResource = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceToken,
                    expectedAudience: issuer,
                    expectedAgentJkt: issuance.ConfirmationKey.ComputeJwkThumbprint(),
                    metadata,
                    jwks,
                    expectedPersonServer: caller.Identifier,
                    cancellationToken: context.RequestAborted);
                verifiedPresented = await tokenVerifier.VerifyPresentedTokenAsync(
                    presentedToken, verifiedResource, metadata, jwks, context.RequestAborted);
                issuance.ValidateResourceContext(verifiedResource.Payload);
                r3DocumentClaims = R3ClaimReader.ReadResourceDocument(verifiedResource.Payload)
                    ?? throw new TokenVerificationException("resource_token missing r3_uri/r3_s256");
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.TokenFailure(ex, TokenCredential.Resource);
            }
            catch (InvalidOperationException ex)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_resource_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }

            try
            {
                await TokenRegistration.RegisterAsync(inventory,
                    [.. issuance.SourceTokens, TokenRegistration.FromVerified(verifiedPresented, TokenCredential.Presented)], context.RequestAborted);
            }
            catch (TokenVerificationException ex) { return AAuth.Server.AAuthProblemDetails.SourceRevoked(ex); }

            var resourceIssuer = (string?)verifiedResource.Payload["iss"];
            if (string.IsNullOrWhiteSpace(resourceIssuer))
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_resource_token", "resource_token missing iss", statusCode: StatusCodes.Status400BadRequest);
            }

            AuthMintParts mintParts;
            try
            {
                mintParts = await EvaluateDocumentAsync(context, options, r3DocumentClaims, resourceIssuer, context.RequestAborted);
                mintParts = mintParts with
                {
                    MissionS256 = verifiedResource.MissionS256,
                    PersonServer = caller.Identifier,
                    Subject = verifiedResource.Subject!,
                    Tenant = verifiedResource.Tenant,
                    ExpiresAt = verifiedPresented.ExpiresAt < issuance.ExpiresAt ? verifiedPresented.ExpiresAt : issuance.ExpiresAt,
                };
                var scope = (string?)verifiedResource.Payload["scope"];
                if (scope is not null)
                {
                    var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (scopes.Length == 0 || scopes.Any(value => options.IsScopeAllowed?.Invoke(resourceIssuer, value) != true))
                        throw new InvalidOperationException("Resource scopes require independent AS policy approval.");
                    mintParts = mintParts with { Scope = scope };
                }
            }
            catch (Exception ex) when (ex is R3HashMismatchException or InvalidOperationException or HttpRequestException or TaskCanceledException or TokenVerificationException or ArgumentException or System.Text.Json.JsonException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("r3_evaluation_failed", ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }

            // Per-call proposal + human consent (r3 §Per-Call Proposals, Flow step 2:
            // "the PS renders `display` for user consent. On approval, the AS issues a
            // per-call auth token"). Park the decision and return 202 requirement=interaction
            // so the PS relays the consent link; mint only after the user approves (below).
            if (mintParts.IssuanceKind == R3TokenIssuanceKind.Proposal && options.RequireProposalConsent)
            {
                var entry = pendingStore.Add(mintParts, issuance, resourceIssuer, caller.Identifier);
                entry.OwnerKeyThumbprint = caller.KeyThumbprint;
                context.Response.Headers.Location = $"{pendingPath}/{entry.Id}";
                context.Response.Headers["Retry-After"] = "1";
                context.Response.Headers["Cache-Control"] = "no-store";
                context.Response.Headers[AAuthRequirementHeader.Name] = Interaction.Format($"{issuer}{consentPath}", entry.Browser.Code, options.EgressPolicy);
                return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }

            // Replay defence on the granted immediate-mint path ONLY (§Freshness and
            // Replay). This branch mints + audits synchronously and is never legitimately
            // re-issued (a granted /token is a single POST → 200), so a verbatim replay
            // here is an attack and is refused. The proposal branch above is deliberately
            // excluded: the agent re-drives it while polling (identical sub-second POSTs),
            // and its per-call mint is already made exactly-once by the /pending gate.
            // No-op unless an IJtiStore is registered (preserves prior behaviour).
            if (!await R3DocumentEndpoint.TryRecordMintSignatureAsync(context, caller.KeyThumbprint))
            {
                context.Response.Headers[AAuth.Errors.SignatureError.HeaderName] = AAuth.Errors.SignatureError.Format(AAuth.Errors.SignatureErrorCode.InvalidSignature);
                return AAuth.Server.AAuthProblemDetails.Create("invalid_signature", "replayed request signature", statusCode: StatusCodes.Status401Unauthorized);
            }

            try
            {
                var authToken = await MintAndAuditAsync(mintParts, issuance, resourceIssuer, context.RequestAborted);
                return await AuthTokenResponse.CreateTrackedAsync(() => authToken, issuance.ExpiresAt,
                    inventory, issuance.SourceTokens.Select(source => source.Token).ToArray(), options.TimeProvider, context.RequestAborted);
            }
            catch (AuthTokenExpiredException) { return AuthTokenResponse.Expired(); }
        });

        // GET /pending/{id} — polled (PS federation client, signed) after the 202
        // relay. Returns the minted per-call token once the user approves at the
        // consent screen; 202 while pending; 403 when denied.
        app.MapMethods(pendingPath + "/{id}", ["GET", "DELETE"], async (HttpContext context, string id) =>
        {
            // The PS polls this Location over its signed federation channel; verify
            // the HTTP signature and trusted-PS identity exactly like /token (the
            // deferred poll rides the same authenticated PS→AS channel, §AS Token
            // Endpoint). The browser /interaction/consent endpoints stay unsigned.
            string pollerPersonServer;
            string? pollerKey;
            try
            {
                var poller = await R3DocumentEndpoint.VerifyFetcherAsync(context, options.IsCallerTrustedPersonServer);
                if (!options.IsCallerTrustedPersonServer(poller))
                {
                    return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", statusCode: StatusCodes.Status403Forbidden);
                }
                pollerPersonServer = poller.Identifier;
                pollerKey = poller.KeyThumbprint;
            }
            catch (R3UntrustedJwksUriException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", statusCode: StatusCodes.Status403Forbidden);
            }
            catch (Exception ex) when (ex is R3FetchVerificationException or AAuth.HttpSig.AAuthVerificationException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_signature", ex.Message, statusCode: StatusCodes.Status401Unauthorized);
            }

            var entry = pendingStore.Get(id);
            if (entry is null)
            {
                return DeferredState.Missing(id);
            }
            // Same-PS re-pin: only the PS that parked this proposal may poll it — a
            // different trusted PS must not receive the token or trigger the mint/audit
            // (cross-PS pending isolation; mirrors the core AS's AuthorizePsCaller).
            if (!string.Equals(pollerPersonServer, entry.OriginPersonServer, StringComparison.Ordinal)
                || !string.Equals(pollerKey, entry.OwnerKeyThumbprint, StringComparison.Ordinal))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", "pending entry belongs to a different Person Server", statusCode: StatusCodes.Status403Forbidden);
            }
            return await entry.Lifecycle.ExecuteAsync(context, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                if (HttpMethods.IsDelete(context.Request.Method))
                {
                    entry.Lifecycle.Cancel();
                    return Results.NoContent();
                }
                switch (entry.Status)
                {
                    case R3PendingStatus.Allowed:
                        if (entry.Issuance.ExpiresAt.ToUnixTimeSeconds() <= options.TimeProvider.GetUtcNow().ToUnixTimeSeconds())
                            return AuthTokenResponse.Expired();
                        if (entry.AuthToken is null)
                        {
                            // Mint-once gate: concurrent polls of the same approval must not
                            // mint (and audit) the token more than once (§Audit Log Integrity).
                            // The outer null-check keeps the common already-minted poll lock-free;
                            // the inner ??= re-checks under the per-entry gate.
                            await entry.MintGate.WaitAsync(context.RequestAborted);
                            try
                            {
                                entry.AuthToken ??= await MintAndAuditAsync(entry.MintParts, entry.Issuance, entry.ResourceIssuer, context.RequestAborted);
                            }
                            catch (AuthTokenExpiredException) { return AuthTokenResponse.Expired(); }
                            finally
                            {
                                entry.MintGate.Release();
                            }
                        }
                        return await AuthTokenResponse.CreateTrackedAsync(() => entry.AuthToken, entry.Issuance.ExpiresAt,
                            inventory, entry.Issuance.SourceTokens.Select(source => source.Token).ToArray(), options.TimeProvider, context.RequestAborted);
                    case R3PendingStatus.Denied:
                        return AAuth.Server.AAuthProblemDetails.Create("denied", statusCode: StatusCodes.Status403Forbidden);
                    default:
                        context.Response.Headers.Location = $"{pendingPath}/{id}";
                        context.Response.Headers["Retry-After"] = "1";
                        context.Response.Headers["Cache-Control"] = "no-store";
                        context.Response.Headers[AAuthRequirementHeader.Name] = Interaction.Format($"{issuer}{consentPath}", entry.Browser.Code, options.EgressPolicy);
                        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
                }
            });
        });

        // Browser consent screen for a per-call proposal — renders the proposal's
        // `display` and flips the pending entry on Approve/Deny.
        //
        app.MapMethods(consentPath, ["GET", "POST"], async (HttpContext context) =>
        {
            var entered = await browserConsent.EnterAsync(context, code => pendingStore.GetByCode(code) is { } candidate
                ? new BrowserPendingRequest(candidate.Id, candidate.PendingExpiresAt, candidate.Browser, candidate.Lifecycle) : null);
            if (entered.Error is not null) return entered.Error;
            var entry = pendingStore.Get(entered.Id!);
            return entry is null
                ? Results.Content(R3ConsentHtml.NotFound(issuer), "text/html", null, StatusCodes.Status404NotFound)
                : Results.Content(R3ConsentHtml.Prompt(issuer, consentPath, browserConsent.Fields(context, entered.Decision!), entry), "text/html");
        });
        app.MapPost(consentPath + "/approve", async (HttpContext context) =>
        {
            var decision = await browserConsent.DecideAsync(context);
            if (decision.Error is not null) return decision.Error;
            var entry = pendingStore.Get(decision.Decision!.Id);
            if (entry is null)
            {
                return Results.Content(R3ConsentHtml.NotFound(issuer), "text/html", null, StatusCodes.Status404NotFound);
            }
            return await decision.Decision.ApplyAsync(context, () =>
            {
                if (entry.Status != R3PendingStatus.Pending || entry.Lifecycle.Delivered || entry.Lifecycle.Cancelled
                    || entry.PendingExpiresAt <= options.TimeProvider.GetUtcNow())
                    return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
                entry.Status = R3PendingStatus.Allowed;
                return Results.Content(R3ConsentHtml.Approved(issuer), "text/html");
            });
        });
        app.MapPost(consentPath + "/deny", async (HttpContext context) =>
        {
            var decision = await browserConsent.DecideAsync(context);
            if (decision.Error is not null) return decision.Error;
            var entry = pendingStore.Get(decision.Decision!.Id);
            if (entry is null)
            {
                return Results.Content(R3ConsentHtml.NotFound(issuer), "text/html", null, StatusCodes.Status404NotFound);
            }
            return await decision.Decision.ApplyAsync(context, () =>
            {
                if (entry.Status != R3PendingStatus.Pending || entry.Lifecycle.Delivered || entry.Lifecycle.Cancelled
                    || entry.PendingExpiresAt <= options.TimeProvider.GetUtcNow())
                    return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
                entry.Status = R3PendingStatus.Denied;
                return Results.Content(R3ConsentHtml.Denied(issuer), "text/html");
            });
        });

        return app;
    }

    private static async Task<AuthMintParts> EvaluateDocumentAsync(
        HttpContext context,
        R3AccessTokenEndpointOptions options,
        R3ClaimReader.ResourceDocumentClaims r3,
        string resourceIssuer,
        CancellationToken cancellationToken)
    {
        var bytes = await FetchAsync(context, options, r3.Uri, r3.S256, resourceIssuer, cancellationToken);
        if (IsProposal(bytes))
        {
            var proposal = R3ProposalDocument.FromUtf8Bytes(bytes, schemas: options.VocabularySchemas);
            if (!AccountBinding.Matches(r3.Account, proposal.Account))
                throw new TokenVerificationException("R3 proposal account differs from resource token.");
            if (options.IsOperationAllowed?.Invoke(new(proposal.Vocabulary, proposal.Operations[0])) == false ||
                options.IsProposalAllowed?.Invoke(proposal) == false)
                throw new InvalidOperationException("R3 proposal denied by access server policy.");
            return new AuthMintParts(
                r3.Uri,
                r3.S256,
                new R3Grant { Vocabulary = proposal.Vocabulary, Operations = proposal.Operations },
                null,
                R3TokenIssuanceKind.Proposal,
                proposal.Display?.Summary,
                proposal.Display?.Detail,
                proposal.Account);
        }

        var document = R3Document.FromUtf8Bytes(bytes, schemas: options.VocabularySchemas);
        if (!AccountBinding.Matches(r3.Account, document.Account))
            throw new TokenVerificationException("R3 document account differs from resource token.");
        // Spec (r3 §Auth Token Extensions): the AS — not the resource — decides which
        // operations to grant outright vs make conditional, from the document's
        // `operations` and its OWN policy. The default policy grants everything
        // (`r3_conditional` is OPTIONAL); a dedicated AS supplies IsConditionalOperation.
        var isConditional = options.IsConditionalOperation ?? (static _ => false);
        var granted = new List<R3Operation>();
        var conditional = new List<R3Operation>();
        foreach (var operation in document.Operations)
        {
            var identity = new R3OperationIdentity(document.Vocabulary, operation);
            if (options.IsOperationAllowed?.Invoke(identity) == false) continue;
            (isConditional(identity) ? conditional : granted).Add(operation);
        }
        return new AuthMintParts(
            r3.Uri,
            r3.S256,
            new R3Grant { Vocabulary = document.Vocabulary, Operations = granted },
            conditional.Count == 0 ? null : new R3Grant { Vocabulary = document.Vocabulary, Operations = conditional },
            R3TokenIssuanceKind.Class, Account: document.Account);
    }

    private static async Task<byte[]> FetchAsync(
        HttpContext context,
        R3AccessTokenEndpointOptions options,
        string uri,
        string s256,
        string resourceIssuer,
        CancellationToken cancellationToken)
    {
        R3FetchClient.ValidateFetchTarget(uri, resourceIssuer, options.EgressPolicy);
        if (options.FetchAndVerifyAsync is not null)
        {
            if (options.FetchTransportContract is null || !Enum.IsDefined(options.FetchTransportContract.Value))
                throw new InvalidOperationException("Custom R3 fetch callbacks require an explicit transport contract.");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(options.EgressPolicy.RequestTimeout);
            var bytes = await options.FetchAndVerifyAsync(context, uri, s256, resourceIssuer, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
            if (bytes.Length > options.EgressPolicy.MaxResponseBytes) throw new HttpRequestException("R3 response exceeds the configured byte limit.");
            R3Hash.Verify(bytes, s256);
            return bytes;
        }

        var (kid, key) = options.FirstSigningKey();
        using var client = R3FetchClient.Create(key, options.Issuer, AAuthConstants.DwkFiles.Access, kid,
            options.FetchHttpMessageHandler, options.EgressPolicy, options.FetchTransportContract);
        return await client.FetchAndVerifyAsync(uri, s256, resourceIssuer, cancellationToken).ConfigureAwait(false);
    }

    private static T GetRequired<T>(HttpContext context) where T : notnull =>
        context.RequestServices.GetRequiredService<T>();

    private static T GetServiceOrDefault<T>(HttpContext context, T fallback) where T : class =>
        context.RequestServices.GetService<T>() ?? fallback;

    internal sealed record AuthMintParts(
        string Uri,
        string S256,
        R3Grant Granted,
        R3Grant? Conditional,
        R3TokenIssuanceKind IssuanceKind,
        string? DisplaySummary = null,
        string? DisplayDetail = null,
        string? Account = null,
        string? Scope = null,
        string? MissionS256 = null,
        string PersonServer = "",
        string Subject = "",
        string? Tenant = null,
        DateTimeOffset? ExpiresAt = null);

    private static bool IsProposal(byte[] bytes)
    {
        try
        {
            var node = JsonNode.Parse(bytes) as JsonObject;
            return node?.ContainsKey("parameters") == true;
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new InvalidOperationException("R3 document is not valid JSON.", ex);
        }
    }

    internal enum R3PendingStatus { Pending, Allowed, Denied }

    internal sealed class R3PendingEntry
    {
        public required string Id { get; init; }
        public BrowserInteraction Browser { get; } = new();
        public DeferredState Lifecycle { get; } = new();
        public string? OwnerKeyThumbprint { get; set; }
        public DateTimeOffset PendingExpiresAt => CreatedAt.AddMinutes(10) < Issuance.ExpiresAt
            ? CreatedAt.AddMinutes(10) : Issuance.ExpiresAt;
        public required AuthMintParts MintParts { get; init; }
        public required AgentIssuanceContext Issuance { get; init; }
        public string AgentId => Issuance.AgentId;
        public required string ResourceIssuer { get; init; }
        public required DateTimeOffset CreatedAt { get; init; }
        // The jwks_uri authority of the PS that parked this entry via /token. Only that
        // same PS may poll /pending for it (cross-PS pending isolation).
        public required string OriginPersonServer { get; init; }
        public R3PendingStatus Status { get; set; } = R3PendingStatus.Pending;
        public string? AuthToken { get; set; }

        // Serializes the mint-once check on the /pending poll so concurrent polls
        // of the same approval don't mint (and audit) more than one token.
        public SemaphoreSlim MintGate { get; } = new(1, 1);
    }

    internal sealed class R3PendingStore
    {
        // Bounded lifetime so abandoned consent flows (or a client spamming per-call
        // proposals) don't grow the store without bound; mirrors the core in-memory
        // pending stores (InMemoryAccessPendingStore / InMemoryPersonPendingStore).
        internal static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

        private readonly ConcurrentDictionary<string, R3PendingEntry> _entries = new(StringComparer.Ordinal);
        private readonly TimeProvider _timeProvider;

        public R3PendingStore(TimeProvider timeProvider) => _timeProvider = timeProvider;

        public R3PendingEntry Add(AuthMintParts mintParts, AgentIssuanceContext issuance, string resourceIssuer, string originPersonServer)
        {
            Sweep();
            var entry = new R3PendingEntry
            {
                Id = Guid.NewGuid().ToString("N"),
                MintParts = mintParts,
                Issuance = issuance,
                ResourceIssuer = resourceIssuer,
                CreatedAt = _timeProvider.GetUtcNow(),
                OriginPersonServer = originPersonServer,
            };
            _entries[entry.Id] = entry;
            return entry;
        }

        public R3PendingEntry? Get(string id)
        {
            Sweep();
            return _entries.TryGetValue(id, out var entry) ? entry : null;
        }

        public R3PendingEntry? GetByCode(string code)
        {
            Sweep();
            var normalized = InteractionCode.Normalize(code);
            return _entries.Values.FirstOrDefault(entry => entry.Browser.Code == normalized);
        }

        // Drop entries past the TTL so the dictionary does not grow without bound.
        private void Sweep()
        {
            var cutoff = _timeProvider.GetUtcNow() - Ttl - TimeSpan.FromHours(1);
            foreach (var kv in _entries)
            {
                if (kv.Value.CreatedAt < cutoff)
                {
                    _entries.TryRemove(kv.Key, out _);
                }
            }
        }
    }

    // Browser consent screen for a per-call proposal. Mirrors the Federated AS's
    // consent screen (red **Access Server** banner + the same button.approve/
    // button.deny selectors) so the shared demo tooling works; renders the
    // proposal's `display` for the user's decision.
    private static class R3ConsentHtml
    {
        private const string Style =
            "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#b91c1c;color:#fff;"
            + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
            + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#fecaca}"
            + ".sub{color:#777;font-size:.85rem;margin:.35rem 0 1.25rem}"
            + "h1{font-size:1.25rem}code{background:#f3f4f6;padding:.1rem .3rem;border-radius:.2rem}"
            + "pre{background:#f3f4f6;padding:.75rem;border-radius:.4rem;white-space:pre-wrap}"
            + "form{margin-top:1.5rem;display:inline-flex;gap:.75rem}"
            + "button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;border-radius:.25rem;border:1px solid #999}"
            + "button.approve{background:#6ee7b7;border-color:#34d399}"
            + "button.deny{background:#fecaca;border-color:#f87171}</style>";

        private static string Authority(string issuer) =>
            Uri.TryCreate(issuer, UriKind.Absolute, out var u) ? u.Authority : issuer;

        private static string Banner(string issuer) =>
            "<div class=badge><span class=dot></span>R3 Access Server</div>"
            + $"<div class=sub>{Enc(Authority(issuer))} — evaluates the per-call proposal and issues the R3 auth token</div>";

        private static string Page(string issuer, string title, string body) =>
            "<!doctype html><meta charset=utf-8><title>" + Enc(title) + " — R3 Access Server</title>"
            + Style + Banner(issuer) + body;

        public static string Prompt(string issuer, string consentPath, string fields, R3PendingEntry entry)
        {
            var op = entry.MintParts.Granted.Operations.Count > 0 ? entry.MintParts.Granted.Operations[0].Id : "(operation)";
            var summary = entry.MintParts.DisplaySummary is { Length: > 0 } s ? $"<p>{Enc(s)}</p>" : string.Empty;
            var detail = entry.MintParts.DisplayDetail is { Length: > 0 } d ? $"<pre>{Enc(d)}</pre>" : string.Empty;
            return Page(issuer, "Approve this action",
                "<h1>Approve a per-call action</h1>"
                + "<p>An agent is requesting your approval for a specific, consequential action — "
                + "review the details below before approving.</p>"
                + $"<div><b>Operation:</b> <code>{Enc(op)}</code></div>"
                + summary + detail
                + $"<form method=post action=\"{Enc(consentPath)}/approve\">"
                + fields
                + "<button class=approve type=submit>Approve</button></form>"
                + $"<form method=post action=\"{Enc(consentPath)}/deny\">"
                + fields
                + "<button class=deny type=submit>Deny</button></form>");
        }

        public static string Approved(string issuer) =>
            Page(issuer, "Approved",
                "<h1>Approved</h1><p>The per-call action was approved. You can close this tab — "
                + "the agent will receive its per-call auth token on its next poll.</p>");

        public static string Denied(string issuer) =>
            Page(issuer, "Denied",
                "<h1>Denied</h1><p>The per-call action was denied. The agent's next poll will "
                + "receive <code>403 denied</code>. You can close this tab.</p>");

        public static string NotFound(string issuer) =>
            Page(issuer, "Unknown or expired code",
                "<h1>Unknown or expired code</h1><p>This approval request is no longer pending.</p>");

        private static string Enc(string value) => WebUtility.HtmlEncode(value);
    }
}

public sealed class R3AccessTokenEndpointOptions
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; init; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    public AAuth.Discovery.AAuthTransportContract? FetchTransportContract { get; init; }
    public required string Issuer { get; init; }
    public required IReadOnlyDictionary<string, IAAuthKey> SigningKeys { get; init; }
    public string TokenPath { get; init; } = "/token";
    /// <summary>
    /// Person Servers this AS brokers for, by authority (or absolute URL). <c>null</c>
    /// ⇒ broker any *verifiable* PS (the AAuth spec default); empty ⇒ deny-all;
    /// entries narrow. Composed by AND with <see cref="IsTrustedPersonServer"/>.
    /// </summary>
    public IReadOnlyCollection<string>? TrustedPersonServers { get; init; }

    /// <summary>
    /// Optional per-PS trust policy. Input: the caller PS's <c>jwks_uri</c> authority.
    /// Composed by AND with <see cref="TrustedPersonServers"/> — each only narrows;
    /// <c>null</c> ⇒ no policy constraint. Both unset ⇒ broker any verifiable PS.
    /// See <see cref="AAuth.Server.Verification.IssuerTrust"/>.
    /// </summary>
    public Func<string, bool>? IsTrustedPersonServer { get; init; }

    public Func<HttpContext, string, string, string, CancellationToken, Task<byte[]>>? FetchAndVerifyAsync { get; init; }

    /// <summary>
    /// Optional inner <see cref="HttpMessageHandler"/> for the AS's signed R3-document
    /// fetch. Defaults to a real network handler; tests (and in-proc compositions) set
    /// this to a <c>TestServer</c> handler so the AS can fetch the resource's document
    /// over the loopback pipeline. Ignored when <see cref="FetchAndVerifyAsync"/> is set.
    /// </summary>
    public HttpMessageHandler? FetchHttpMessageHandler { get; init; }
    /// <summary>
    /// Required audit persistence. Completion must mean the token association is committed;
    /// failure prevents token release. In-memory implementations are not crash-durable.
    /// </summary>
    public required IR3AuditSink AuditSink { get; init; }
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
    public R3VocabularySchemas VocabularySchemas { get; init; } = R3VocabularySchemas.Standard;
    public Func<R3OperationIdentity, bool>? IsOperationAllowed { get; init; }
    public Func<R3ProposalDocument, bool>? IsProposalAllowed { get; init; }
    public Func<string, string, bool>? IsScopeAllowed { get; init; }

    /// <summary>
    /// AS policy deciding which R3 operations are <c>r3_conditional</c> (require
    /// per-call approval) rather than <c>r3_granted</c> outright. Per r3 §Auth Token
    /// Extensions the AS — not the resource — makes this decision "based on the
    /// operations defined in the R3 document and its own policy." Input: each
    /// operation from the fetched document; return <c>true</c> ⇒ conditional.
    /// <c>null</c> (default) ⇒ grant every operation (<c>r3_conditional</c> is OPTIONAL).
    /// </summary>
    public Func<R3OperationIdentity, bool>? IsConditionalOperation { get; init; }

    /// <summary>
    /// When <see langword="true"/>, a per-call proposal (r3 §Per-Call Proposals) is not
    /// auto-minted: the AS parks the decision and returns <c>202 requirement=interaction</c>
    /// (relayed by the PS), rendering the proposal's <c>display</c> at <see cref="ConsentPath"/>
    /// for the user to approve; the per-call token is minted only after approval, on the
    /// <see cref="PendingPath"/> poll. Whether a proposal requires human consent or is
    /// machine-evaluated is deployment policy (r3 §Per-Call Proposals). Default
    /// <see langword="false"/> (auto-mint) to preserve the non-interactive path.
    /// </summary>
    public bool RequireProposalConsent { get; init; }
    public BrowserConsentSessions? BrowserConsent { get; init; }

    /// <summary>Browser consent-screen path for per-call proposals. Default <c>/interaction/consent</c>.</summary>
    public string ConsentPath { get; init; } = "/interaction/consent";

    /// <summary>Pending-poll path used to relay/mint after per-call consent. Default <c>/pending</c>.</summary>
    public string PendingPath { get; init; } = "/pending";

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new InvalidOperationException("Issuer must be set.");
        }
        if (SigningKeys is null || SigningKeys.Count == 0)
        {
            throw new InvalidOperationException("At least one AS signing key is required.");
        }
        if (string.IsNullOrWhiteSpace(TokenPath))
        {
            throw new InvalidOperationException("TokenPath must be set.");
        }
        if (AuditSink is null)
        {
            throw new InvalidOperationException("AuditSink must be set.");
        }
        if (TimeProvider is null)
        {
            throw new InvalidOperationException("TimeProvider must be set.");
        }
        if (string.IsNullOrWhiteSpace(ConsentPath))
        {
            throw new InvalidOperationException("ConsentPath must be set.");
        }
        if (string.IsNullOrWhiteSpace(PendingPath))
        {
            throw new InvalidOperationException("PendingPath must be set.");
        }
    }

    internal (string Kid, IAAuthKey Key) FirstSigningKey()
    {
        foreach (var pair in SigningKeys)
        {
            return (pair.Key, pair.Value);
        }
        throw new InvalidOperationException("At least one AS signing key is required.");
    }

    // draft-08 PS-AS trust: `TrustedPersonServers` null ⇒ open (broker any *verifiable*
    // Person Server — the spec default); empty ⇒ deny-all; entries narrow. Composed by
    // AND with the optional `IsTrustedPersonServer` policy via the shared IssuerTrust
    // helper (same decision path as the core Access Server).
    internal bool IsCallerTrustedPersonServer(R3VerifiedFetcher fetcher)
    {
        // The PS authenticates via the jwks_uri scheme; a jwt-scheme (agent) caller is never a PS.
        if (fetcher.Scheme != AAuthConstants.Schemes.JwksUri
            || !string.Equals(fetcher.ParsedKey.Dwk, AAuthConstants.DwkFiles.Person, StringComparison.Ordinal))
        {
            return false;
        }
        EgressPolicy.ValidateIdentifier(fetcher.Identifier);
        foreach (var identifier in TrustedPersonServers ?? []) EgressPolicy.ValidateIdentifier(identifier);
        return IssuerTrust.IsTrusted(TrustedPersonServers, IsTrustedPersonServer, fetcher.Identifier);
    }
}

using System.Collections.Concurrent;
using System.Net;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.R3.Model;
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
        var issuer = options.Issuer.TrimEnd('/');
        var tokenPath = "/" + options.TokenPath.Trim('/');

        WellKnownEndpoints.MapAAuthAccessServerWellKnown(app, new AAuthAccessServerMetadataOptions
        {
            Issuer = issuer,
            TokenEndpoint = $"{issuer}{tokenPath}",
            SigningKeys = options.SigningKeys,
        });

        var pendingPath = "/" + options.PendingPath.Trim('/');
        var consentPath = "/" + options.ConsentPath.Trim('/');
        var pendingStore = new R3PendingStore(options.TimeProvider);

        // Mint the R3 auth token + write the audit record atomically. Shared by the
        // /token happy path (granted class docs) and the /pending poll after per-call
        // human consent (r3 §Per-Call Proposals, Flow step 2 + §Audit Log Integrity).
        async Task<string> MintAndAuditAsync(AuthMintParts parts, string agentId, IAAuthKey agentKey, string resourceIssuer, CancellationToken ct)
        {
            var claims = R3AuthClaims.AuthToken(parts.Uri, parts.S256, parts.Granted, parts.Conditional);
            var token = new AuthTokenBuilder
            {
                Issuer = issuer,
                Audience = resourceIssuer,
                Agent = agentId,
                AgentConfirmationKey = agentKey,
                Key = signingKey,
                KeyId = signingKid,
                Dwk = AuthTokenBuilder.AccessDwk,
                Subject = options.Subject,
                AdditionalClaims = claims,
            }.Build();
            await options.AuditSink.RecordTokenIssuanceAsync(new R3TokenIssuanceAuditRecord(
                parts.Uri, parts.S256, agentId, resourceIssuer, issuer,
                options.TimeProvider.GetUtcNow(), parts.IssuanceKind), ct);
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
                return Results.Json(new { error = "untrusted_person_server" }, statusCode: StatusCodes.Status403Forbidden);
            }
            catch (Exception ex) when (ex is R3FetchVerificationException or AAuth.HttpSig.AAuthVerificationException)
            {
                return Results.Json(new { error = "invalid_signature", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!options.IsCallerTrustedPersonServer(caller))
            {
                return Results.Json(new { error = "untrusted_person_server" }, statusCode: StatusCodes.Status403Forbidden);
            }

            JsonObject? body;
            try
            {
                body = await context.Request.ReadFromJsonAsync<JsonObject>();
            }
            catch (System.Text.Json.JsonException)
            {
                return Results.Json(new { error = "invalid_request", detail = "body is not valid JSON" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var agentToken = (string?)body?["agent_token"];
            var resourceToken = (string?)body?["resource_token"];
            if (string.IsNullOrWhiteSpace(agentToken) || string.IsNullOrWhiteSpace(resourceToken))
            {
                return Results.Json(new { error = "invalid_request", detail = "missing agent_token or resource_token" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var tokenVerifier = GetServiceOrDefault(context, new TokenVerifier());
            var metadata = GetRequired<MetadataClient>(context);
            var jwks = GetRequired<JwksClient>(context);

            string agentId;
            IAAuthKey agentConfirmationKey;
            try
            {
                var verifiedAgent = await tokenVerifier.VerifyWithJwksAsync(
                    agentToken,
                    metadata,
                    jwks,
                    AgentTokenBuilder.TokenType,
                    AgentTokenBuilder.AgentDwk,
                    expectedAudience: null,
                    cancellationToken: context.RequestAborted);
                agentId = (string?)verifiedAgent.Payload["sub"]
                    ?? throw new TokenVerificationException("agent_token missing sub");
                var cnfJwk = verifiedAgent.Payload["cnf"]?["jwk"] as JsonObject
                    ?? throw new TokenVerificationException("agent_token missing cnf.jwk");
                agentConfirmationKey = KeyFactory.FromJwk(cnfJwk);
            }
            catch (TokenVerificationException ex)
            {
                return Results.Json(new { error = "invalid_agent_token", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized);
            }

            TokenVerifier.VerifiedToken verifiedResource;
            R3ClaimReader.ResourceDocumentClaims r3DocumentClaims;
            try
            {
                verifiedResource = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceToken,
                    expectedAudience: issuer,
                    expectedAgentId: agentId,
                    expectedAgentJkt: agentConfirmationKey.ComputeJwkThumbprint(),
                    metadata,
                    jwks,
                    cancellationToken: context.RequestAborted);
                r3DocumentClaims = R3ClaimReader.ReadResourceDocument(verifiedResource.Payload)
                    ?? throw new TokenVerificationException("resource_token missing r3_uri/r3_s256");
            }
            catch (Exception ex) when (ex is TokenVerificationException or InvalidOperationException)
            {
                return Results.Json(new { error = "invalid_resource_token", detail = ex.Message }, statusCode: StatusCodes.Status400BadRequest);
            }

            var resourceIssuer = (string?)verifiedResource.Payload["iss"];
            if (string.IsNullOrWhiteSpace(resourceIssuer))
            {
                return Results.Json(new { error = "invalid_resource_token", detail = "resource_token missing iss" }, statusCode: StatusCodes.Status400BadRequest);
            }

            AuthMintParts mintParts;
            try
            {
                mintParts = await EvaluateDocumentAsync(context, options, r3DocumentClaims, resourceIssuer, context.RequestAborted);
            }
            catch (Exception ex) when (ex is R3HashMismatchException or InvalidOperationException or HttpRequestException or TaskCanceledException)
            {
                return Results.Json(new { error = "r3_evaluation_failed", detail = ex.Message }, statusCode: StatusCodes.Status400BadRequest);
            }

            // Per-call proposal + human consent (r3 §Per-Call Proposals, Flow step 2:
            // "the PS renders `display` for user consent. On approval, the AS issues a
            // per-call auth token"). Park the decision and return 202 requirement=interaction
            // so the PS relays the consent link; mint only after the user approves (below).
            if (mintParts.IssuanceKind == R3TokenIssuanceKind.Proposal && options.RequireProposalConsent)
            {
                var entry = pendingStore.Add(mintParts, agentId, agentConfirmationKey, resourceIssuer, caller.JwksUri!.Authority);
                context.Response.Headers.Location = $"{pendingPath}/{entry.Id}";
                context.Response.Headers["Retry-After"] = "1";
                context.Response.Headers["Cache-Control"] = "no-store";
                context.Response.Headers[AAuthRequirementHeader.Name] = Interaction.Format($"{issuer}{consentPath}", entry.Id);
                return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }

            var authToken = await MintAndAuditAsync(mintParts, agentId, agentConfirmationKey, resourceIssuer, context.RequestAborted);
            return Results.Ok(new { auth_token = authToken, expires_in = 3600 });
        });

        // GET /pending/{id} — polled (PS federation client, signed) after the 202
        // relay. Returns the minted per-call token once the user approves at the
        // consent screen; 202 while pending; 403 when denied.
        app.MapGet(pendingPath + "/{id}", async (HttpContext context, string id) =>
        {
            // The PS polls this Location over its signed federation channel; verify
            // the HTTP signature and trusted-PS identity exactly like /token (the
            // deferred poll rides the same authenticated PS→AS channel, §AS Token
            // Endpoint). The browser /interaction/consent endpoints stay unsigned.
            string pollerPersonServer;
            try
            {
                var poller = await R3DocumentEndpoint.VerifyFetcherAsync(context, options.IsCallerTrustedPersonServer);
                if (!options.IsCallerTrustedPersonServer(poller))
                {
                    return Results.Json(new { error = "untrusted_person_server" }, statusCode: StatusCodes.Status403Forbidden);
                }
                pollerPersonServer = poller.JwksUri!.Authority;
            }
            catch (R3UntrustedJwksUriException)
            {
                return Results.Json(new { error = "untrusted_person_server" }, statusCode: StatusCodes.Status403Forbidden);
            }
            catch (Exception ex) when (ex is R3FetchVerificationException or AAuth.HttpSig.AAuthVerificationException)
            {
                return Results.Json(new { error = "invalid_signature", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var entry = pendingStore.Get(id);
            if (entry is null)
            {
                return Results.Json(new { error = "unknown_pending" }, statusCode: StatusCodes.Status404NotFound);
            }
            // Same-PS re-pin: only the PS that parked this proposal may poll it — a
            // different trusted PS must not receive the token or trigger the mint/audit
            // (cross-PS pending isolation; mirrors the core AS's AuthorizePsCaller).
            if (!string.Equals(pollerPersonServer, entry.OriginPersonServer, StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(new { error = "untrusted_person_server", detail = "pending entry belongs to a different Person Server" }, statusCode: StatusCodes.Status403Forbidden);
            }
            switch (entry.Status)
            {
                case R3PendingStatus.Allowed:
                    if (entry.AuthToken is null)
                    {
                        // Mint-once gate: concurrent polls of the same approval must not
                        // mint (and audit) the token more than once (§Audit Log Integrity).
                        // The outer null-check keeps the common already-minted poll lock-free;
                        // the inner ??= re-checks under the per-entry gate.
                        await entry.MintGate.WaitAsync(context.RequestAborted);
                        try
                        {
                            entry.AuthToken ??= await MintAndAuditAsync(entry.MintParts, entry.AgentId, entry.AgentConfirmationKey, entry.ResourceIssuer, context.RequestAborted);
                        }
                        finally
                        {
                            entry.MintGate.Release();
                        }
                    }
                    return Results.Ok(new { auth_token = entry.AuthToken, expires_in = 3600 });
                case R3PendingStatus.Denied:
                    return Results.Json(new { error = "denied" }, statusCode: StatusCodes.Status403Forbidden);
                default:
                    context.Response.Headers.Location = $"{pendingPath}/{id}";
                    context.Response.Headers["Retry-After"] = "1";
                    context.Response.Headers["Cache-Control"] = "no-store";
                    context.Response.Headers[AAuthRequirementHeader.Name] = Interaction.Format($"{issuer}{consentPath}", id);
                    return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }
        });

        // Browser consent screen for a per-call proposal — renders the proposal's
        // `display` and flips the pending entry on Approve/Deny.
        //
        // DEMO LIMITATION: like the Federated stub AS, these endpoints do NOT authenticate
        // a human — approval is gated only by knowledge of the single-use `code`. A
        // production R3 AS MUST authenticate the user here (an IdP/login session, as the
        // Federated AS does via Keycloak) so the per-call "human consent" is a real
        // human-presence control and not something the agent can self-approve.
        app.MapGet(consentPath, (string code) =>
        {
            var entry = pendingStore.Get(code);
            return entry is null
                ? Results.Content(R3ConsentHtml.NotFound(issuer), "text/html", null, StatusCodes.Status404NotFound)
                : Results.Content(R3ConsentHtml.Prompt(issuer, consentPath, code, entry), "text/html");
        });
        app.MapPost(consentPath + "/approve", async (HttpContext context) =>
        {
            var code = (await context.Request.ReadFormAsync())["code"].ToString();
            var entry = pendingStore.Get(code);
            if (entry is null)
            {
                return Results.Content(R3ConsentHtml.NotFound(issuer), "text/html", null, StatusCodes.Status404NotFound);
            }
            entry.Status = R3PendingStatus.Allowed;
            return Results.Content(R3ConsentHtml.Approved(issuer), "text/html");
        }).DisableAntiforgery();
        app.MapPost(consentPath + "/deny", async (HttpContext context) =>
        {
            var code = (await context.Request.ReadFormAsync())["code"].ToString();
            var entry = pendingStore.Get(code);
            if (entry is null)
            {
                return Results.Content(R3ConsentHtml.NotFound(issuer), "text/html", null, StatusCodes.Status404NotFound);
            }
            entry.Status = R3PendingStatus.Denied;
            return Results.Content(R3ConsentHtml.Denied(issuer), "text/html");
        }).DisableAntiforgery();

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
            var proposal = R3ProposalDocument.FromUtf8Bytes(bytes);
            return new AuthMintParts(
                r3.Uri,
                r3.S256,
                new R3Grant { Vocabulary = proposal.Vocabulary, Operations = proposal.Operations },
                null,
                R3TokenIssuanceKind.Proposal,
                proposal.Display?.Summary,
                proposal.Display?.Detail);
        }

        var document = R3Document.FromUtf8Bytes(bytes);
        // Spec (r3 §Auth Token Extensions): the AS — not the resource — decides which
        // operations to grant outright vs make conditional, from the document's
        // `operations` and its OWN policy. The default policy grants everything
        // (`r3_conditional` is OPTIONAL); a dedicated AS supplies IsConditionalOperation.
        var isConditional = options.IsConditionalOperation ?? (static _ => false);
        var granted = new List<R3Operation>();
        var conditional = new List<R3Operation>();
        foreach (var operation in document.Operations)
        {
            (isConditional(operation) ? conditional : granted).Add(operation);
        }
        return new AuthMintParts(
            r3.Uri,
            r3.S256,
            new R3Grant { Vocabulary = document.Vocabulary, Operations = granted },
            conditional.Count == 0 ? null : new R3Grant { Vocabulary = document.Vocabulary, Operations = conditional },
            R3TokenIssuanceKind.Class);
    }

    private static async Task<byte[]> FetchAsync(
        HttpContext context,
        R3AccessTokenEndpointOptions options,
        string uri,
        string s256,
        string resourceIssuer,
        CancellationToken cancellationToken)
    {
        R3FetchClient.ValidateFetchTarget(uri, resourceIssuer);
        if (options.FetchAndVerifyAsync is not null)
        {
            return await options.FetchAndVerifyAsync(context, uri, s256, resourceIssuer, cancellationToken).ConfigureAwait(false);
        }

        var (kid, key) = options.FirstSigningKey();
        var client = R3FetchClient.Create(key, $"{options.Issuer.TrimEnd('/')}/.well-known/jwks.json", kid, options.FetchHttpMessageHandler);
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
        string? DisplayDetail = null);

    private static bool IsProposal(byte[] bytes)
    {
        try
        {
            var node = JsonNode.Parse(bytes) as JsonObject;
            return node?["parameters"] is not null;
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
        public required AuthMintParts MintParts { get; init; }
        public required string AgentId { get; init; }
        public required IAAuthKey AgentConfirmationKey { get; init; }
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

        public R3PendingEntry Add(AuthMintParts mintParts, string agentId, IAAuthKey agentKey, string resourceIssuer, string originPersonServer)
        {
            Sweep();
            var entry = new R3PendingEntry
            {
                Id = Guid.NewGuid().ToString("N"),
                MintParts = mintParts,
                AgentId = agentId,
                AgentConfirmationKey = agentKey,
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

        // Drop entries past the TTL so the dictionary does not grow without bound.
        private void Sweep()
        {
            var cutoff = _timeProvider.GetUtcNow() - Ttl;
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

        public static string Prompt(string issuer, string consentPath, string code, R3PendingEntry entry)
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
                + $"<input type=hidden name=code value=\"{Enc(code)}\">"
                + "<button class=approve type=submit>Approve</button></form>"
                + $"<form method=post action=\"{Enc(consentPath)}/deny\">"
                + $"<input type=hidden name=code value=\"{Enc(code)}\">"
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
    public required string Issuer { get; init; }
    public required IReadOnlyDictionary<string, AAuthKey> SigningKeys { get; init; }
    public string TokenPath { get; init; } = "/token";
    public string Subject { get; init; } = "pairwise-sub";
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
    /// AS-side R3 token issuance audit sink. Defaults to no-op for sample ergonomics;
    /// production AS deployments should configure a durable sink. If the configured
    /// sink throws, token issuance is not returned to the caller.
    /// </summary>
    public IR3AuditSink AuditSink { get; init; } = R3NoOpAuditSink.Instance;
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// AS policy deciding which R3 operations are <c>r3_conditional</c> (require
    /// per-call approval) rather than <c>r3_granted</c> outright. Per r3 §Auth Token
    /// Extensions the AS — not the resource — makes this decision "based on the
    /// operations defined in the R3 document and its own policy." Input: each
    /// operation from the fetched document; return <c>true</c> ⇒ conditional.
    /// <c>null</c> (default) ⇒ grant every operation (<c>r3_conditional</c> is OPTIONAL).
    /// </summary>
    public Func<Model.R3Operation, bool>? IsConditionalOperation { get; init; }

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
        if (string.IsNullOrWhiteSpace(Subject))
        {
            throw new InvalidOperationException("Subject must be set.");
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

    internal (string Kid, AAuthKey Key) FirstSigningKey()
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
        if (fetcher.Scheme != AAuthConstants.Schemes.JwksUri || fetcher.JwksUri is null)
        {
            return false;
        }
        IReadOnlyCollection<string>? hosts = TrustedPersonServers is null
            ? null
            : TrustedPersonServers
                .Select(ps => Uri.TryCreate(ps, UriKind.Absolute, out var uri) ? uri.Authority : ps)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return IssuerTrust.IsTrusted(hosts, IsTrustedPersonServer, fetcher.JwksUri.Authority);
    }
}

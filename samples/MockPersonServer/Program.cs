using System.Text.Json.Nodes;
using AAuth;
using AAuth.Access;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Governance;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using MockPersonServer;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Person Server configuration.
//
// For demo purposes the PS generates a fresh Ed25519 signing key on start.
// A production PS would load a stable key from secure storage. Configure
// the issuer URL through `AAuth:Issuer`; default matches launchSettings
// (http://localhost:5100). The issuer URL is also pinned to the value the
// agent puts in its agent token's `ps` claim, so it must match what
// callers configure.
//
// `MockPersonServer:RequireConsent` (default false) controls the user-
// consent gate. When false, every `/token` POST issues an auth token
// immediately — the autonomous-three-party path used by the AgentConsole
// sample and the §3.4 ThreePartyFlow integration test. When true, the PS
// returns 202 + an interaction requirement and the agent must poll the
// pending URL until `POST /admin/consent` records approval — this is what
// drives the GuidedTour's deferred / user-consent showcase and the §3.4
// ThreePartyUserConsentFlow integration test.
// -----------------------------------------------------------------------
var psKey = AAuthKey.Generate();
const string PsKid = "ps-1";
const string PsScope = "whoami";
const string PsAdminScope = "whoami:admin";
// Demo identity claims the mock PS asserts about the user. A production PS
// would resolve these from the signed-in user's directory entry. These let
// the WhoAmI `/jwt/roles` (RBAC) endpoint succeed end-to-end.
//
// Roles/groups are asserted ONLY for recognized "admin" demo agents (those
// whose id is `aauth:demo@...`). Any other agent receives an auth token
// without the role, so role-based DENIAL is exercised end-to-end (a guest
// agent calling `/jwt/roles` gets a 403). A production PS would resolve the
// principal's directory membership instead of a hard-coded prefix.
string[] demoRoles = ["whoami-admin"];
string[] demoGroups = ["demo-users"];
// Identity claims the PS can release for the bound principal when an Access
// Server asks for them via the §Claims Required push. A production PS would
// resolve these from its identity store keyed by the authenticated principal.
var demoUserClaims = new Dictionary<string, string>(StringComparer.Ordinal)
{
    ["email"] = "demo@person.example",
    ["tenant"] = "demo-tenant",
    ["name"] = "Demo User",
};
static bool IsAdminAgent(string agentId) =>
    agentId.StartsWith("aauth:demo@", StringComparison.Ordinal);
var psIssuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5100";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;
var requireConsent = builder.Configuration.GetValue<bool>("MockPersonServer:RequireConsent");
// Four-party (federated) trust: the Access Servers this PS is willing to
// federate to. When a resource token's `aud` is one of these (rather than the
// PS itself), the PS forwards a signed PS->AS token request instead of issuing
// the auth token directly. Pre-established trust — a production PS would manage
// this set per the operator's federation agreements.
var trustedAccessServers = builder.Configuration
        .GetSection("MockPersonServer:TrustedAccessServers").Get<string[]>()
    ?? ["http://localhost:5500"];
var trustedAsSet = new HashSet<string>(
    trustedAccessServers.Select(a => a.TrimEnd('/')), StringComparer.OrdinalIgnoreCase);

builder.Services.AddSingleton(psKey);
builder.Services.AddSingleton(new AAuthVerifier
{
    MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds),
});
builder.Services.AddSingleton(new TokenVerifier());
builder.Services.AddSingleton<MetadataClient>(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
builder.Services.AddHttpClient("aauth-metadata");
builder.Services.AddHttpClient("aauth-jwks");
builder.Services.AddSingleton<ConsentStore>();
builder.Services.AddSingleton<PendingStore>();
builder.Services.AddSingleton<FederatedPendingStore>();

// Mission governance (§PS Governance Endpoints). AddAAuthGovernance registers
// the in-memory mission store + log; the PS supplies the policy/user-channel
// seams (decider / audit sink / interaction relay) and the deterministic
// consent script that stands in for a real user-consent screen.
builder.Services.AddAAuthGovernance();
builder.Services.AddSingleton<MissionConsentScript>();
builder.Services.AddSingleton<MissionPolicyStore>();
builder.Services.AddSingleton<MissionPendingStore>();
builder.Services.AddSingleton<IPermissionDecider, SamplePermissionDecider>();
builder.Services.AddSingleton<IAuditSink, SampleAuditSink>();
builder.Services.AddSingleton<IInteractionRelay, SampleInteractionRelay>();
builder.Services.AddSingleton(sp =>
    new UpstreamTokenValidator(
        sp.GetRequiredService<MetadataClient>(),
        sp.GetRequiredService<JwksClient>()));

// Four-party federation client. The PS signs the PS->AS token request with its
// own key via the `jwks_uri` scheme (the AS resolves the PS's public key from
// `{psIssuer}/.well-known/jwks.json`). The transport handler is the named
// "aauth-federation" client so tests can route it to an in-process AS.
builder.Services.AddHttpClient("aauth-federation");
builder.Services.AddSingleton(sp =>
{
    var metadata = sp.GetRequiredService<MetadataClient>();
    var jwks = sp.GetRequiredService<JwksClient>();
    var validator = new AuthTokenResponseValidator(metadata, jwks);
    var transport = sp.GetRequiredService<IHttpMessageHandlerFactory>()
        .CreateHandler("aauth-federation");
    var signedClient = new AAuthClientBuilder(psKey)
        .UseJwksUri($"{psIssuer.TrimEnd('/')}/.well-known/jwks.json", PsKid)
        .WithInnerHandler(transport)
        .Build();
    return new AccessServerClient(signedClient, metadata, validator);
});

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints — served BEFORE the verification middleware so the
// metadata document and JWKS are reachable without an AAuth signature.
// -----------------------------------------------------------------------

// JWKS (reused from the shared resource helper — same shape).
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = psIssuer,
    ClientName = "Mock Person Server",
    SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [PsScope] = "Issue AAuth auth tokens for WhoAmI",
        [PsAdminScope] = "Issue elevated (admin) AAuth auth tokens for WhoAmI",
    },
    SignatureWindow = signatureWindowSeconds,
});

// PS-specific metadata document.
app.MapAAuthPersonServerWellKnown(new AAuthPersonServerMetadataOptions
{
    Issuer = psIssuer,
    TokenEndpoint = $"{psIssuer.TrimEnd('/')}/token",
    SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
    // Mission governance endpoints (§PS Governance Endpoints). Advertised so an
    // agent's MetadataClient can resolve them from aauth-person.json.
    MissionEndpoint = $"{psIssuer.TrimEnd('/')}/mission",
    PermissionEndpoint = $"{psIssuer.TrimEnd('/')}/permission",
    AuditEndpoint = $"{psIssuer.TrimEnd('/')}/audit",
    InteractionEndpoint = $"{psIssuer.TrimEnd('/')}/mission-interaction",
});

// All other endpoints require an AAuth signature — except the
// /admin/* helpers, which are demo-only consent toggles and intentionally
// unsigned. A production PS would expose these only behind operator auth
// or wouldn't expose them at all.
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
        && !ctx.Request.Path.StartsWithSegments("/admin")
        && !ctx.Request.Path.StartsWithSegments("/interaction"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// -----------------------------------------------------------------------
// POST /token — the exchange endpoint.
//
// Flow:
//   1. AAuthVerificationMiddleware validates the RFC 9421 signature and
//      exposes the parsed carrier token (the agent's aa-agent+jwt) via
//      HttpContext.Items.
//   2. We read `resource_token` from the request body.
//   3. We mint an aa-auth+jwt whose:
//        - iss = this PS
//        - aud = the resource_token's iss (the resource)
//        - agent = agent identifier from the agent token
//        - cnf.jwk = the agent's confirmation key (binds PoP)
//   4. We return { "auth_token": "..." }.
//
// This mock verifies the resource_token per §"Resource Token Verification"
// using the SDK helper TokenVerifier.VerifyResourceTokenAsync (JWKS discovery
// against the issuing resource). A forged or tampered token is rejected.
// -----------------------------------------------------------------------
app.MapPost("/token", async (HttpContext ctx, ConsentStore consent, PendingStore pending) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    // Only an agent token may exchange — refuse anything else.
    var tokenType = ctx.GetAAuthTokenType();
    if (tokenType != AAuthTokenType.AgentToken)
    {
        return Results.Json(
            new { error = "invalid_carrier_token", detail = $"expected {AAuthConstants.TokenTypes.AgentToken}, got {tokenType}" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    var agentId = (string?)parsed.Payload?["sub"];
    if (string.IsNullOrEmpty(agentId))
    {
        return Results.Json(new { error = "invalid_carrier_token", detail = "missing sub" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    JsonObject? body;
    try
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request", detail = "body is not valid JSON" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    var resourceTokenJwt = (string?)body?["resource_token"];
    if (string.IsNullOrEmpty(resourceTokenJwt))
    {
        return Results.Json(new { error = "invalid_request", detail = "missing resource_token" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    var upstreamTokenJwt = (string?)body?["upstream_token"];

    // Four-party (federated) branch. When the resource token's `aud` is NOT
    // this PS, the resource delegated authorization to an Access Server. The PS
    // does not mint the auth token itself — it forwards a signed PS->AS request
    // and returns the AS-issued token. When `aud` IS this PS (the common case),
    // fall through to the three-party path below where the PS acts as its own
    // AS (the "collapsed" PS+AS variant).
    var resourceAudience = PeekJwtAudience(resourceTokenJwt);
    if (resourceAudience is not null
        && !string.Equals(resourceAudience.TrimEnd('/'), psIssuer.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
    {
        // Pre-established trust: only federate to a configured Access Server.
        if (!trustedAsSet.Contains(resourceAudience.TrimEnd('/')))
        {
            return Results.Json(
                new { error = "untrusted_access_server", detail = $"'{resourceAudience}' is not a trusted Access Server." },
                statusCode: StatusCodes.Status403Forbidden);
        }

        var federationVerifier = app.Services.GetRequiredService<TokenVerifier>();
        var federationMetadata = app.Services.GetRequiredService<MetadataClient>();
        var federationJwks = app.Services.GetRequiredService<JwksClient>();

        // Verify the resource token's agent binding before forwarding it — the
        // PS confirms the presenting agent is the one bound to the token
        // (`agent` + `agent_jkt`) and reads the resource URL (`iss`) and scope.
        // The AS re-verifies independently; this guards the PS from relaying a
        // token it has no business relaying.
        string resourceUrl;
        string federatedScope = PsScope;
        try
        {
            var verified = await federationVerifier.VerifyResourceTokenAsync(
                resourceTokenJwt,
                expectedAudience: resourceAudience,
                expectedAgentId: agentId,
                expectedAgentJkt: parsed.ConfirmationKey!.ComputeJwkThumbprint(),
                federationMetadata,
                federationJwks);

            resourceUrl = (string?)verified.Payload["iss"]
                ?? throw new TokenVerificationException("resource_token missing iss");
            var scopeClaim = (string?)verified.Payload["scope"];
            if (!string.IsNullOrWhiteSpace(scopeClaim))
            {
                federatedScope = scopeClaim;
            }
        }
        catch (TokenVerificationException ex)
        {
            var expired = ex.Message.Contains("expired", StringComparison.OrdinalIgnoreCase);
            return Results.Json(
                new { error = expired ? "expired_resource_token" : "invalid_resource_token", detail = ex.Message },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var federation = app.Services.GetRequiredService<AccessServerClient>();
        var fedPending = app.Services.GetRequiredService<FederatedPendingStore>();
        var entry = fedPending.Add();

        // Capture everything the background task needs BEFORE it runs — the
        // HttpContext is gone once we return the response.
        var agentTokenJwt = parsed.Jwt
            ?? throw new InvalidOperationException("Agent token JWT unavailable on the verified request.");
        var agentConfirmationKey = parsed.ConfirmationKey!;
        var fedRequest = new AccessServerRequest
        {
            ResourceToken = resourceTokenJwt,
            AgentToken = agentTokenJwt,
            UpstreamToken = upstreamTokenJwt,
            ExpectedAudience = resourceUrl,
            ExpectedAgentId = agentId,
            AgentKey = agentConfirmationKey,
            RequestedScope = federatedScope,
            // The AS needs an interactive user login/consent. Capture its
            // user-facing interaction URL so the PS can relay it to the agent;
            // FederateAsync keeps polling the AS to completion in the
            // background while the agent polls the PS pending URL.
            OnInteractionRequired = (interaction, _) =>
            {
                entry.InteractionUrl = interaction.Url;
                entry.InteractionCode = interaction.Code;
                entry.FirstAnswer.TrySetResult();
                return Task.CompletedTask;
            },
            // The AS needs identity claims (§Claims Required) for its policy
            // decision. The PS is the identity authority, so it answers with a
            // directed pseudonymous `sub` plus whatever requested claims it
            // holds for the principal. Unknown claims are simply omitted.
            OnClaimsRequired = (claimsRequirement, _) =>
            {
                var claims = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
                foreach (var name in claimsRequirement.RequiredClaims)
                {
                    if (demoUserClaims.TryGetValue(name, out var value))
                    {
                        claims[name] = value;
                    }
                }
                return Task.FromResult(new ClaimsResponse
                {
                    Subject = "pairwise-sub",
                    Claims = claims,
                });
            },
        };

        // Drive the PS->AS federation in the background. The agent's first
        // answer (relayed 202 interaction, or an immediate terminal result
        // when the AS does not need interaction) is decided below.
        _ = Task.Run(async () =>
        {
            try
            {
                var token = await federation.FederateAsync(resourceAudience, fedRequest);
                entry.AuthToken = token;
                entry.Status = FederatedPendingStatus.Allowed;
            }
            catch (AAuthInteractionDeniedException)
            {
                entry.Error = "denied";
                entry.ErrorStatus = StatusCodes.Status403Forbidden;
                entry.Status = FederatedPendingStatus.Denied;
            }
            catch (AAuthTokenExchangeException ex)
            {
                entry.Error = ex.ErrorCode;
                entry.ErrorStatus = ex.StatusCode;
                entry.Status = FederatedPendingStatus.Denied;
            }
            catch (AAuthPaymentRequiredException ex)
            {
                entry.Error = "payment_required";
                entry.ErrorStatus = StatusCodes.Status402PaymentRequired;
                entry.ErrorLocation = ex.Location;
                entry.Status = FederatedPendingStatus.Denied;
            }
            catch (Exception ex)
            {
                // Includes TokenVerificationException (bad AS token) and
                // unreachable-AS failures — surface as an upstream error.
                entry.Error = "federation_failed";
                entry.ErrorStatus = StatusCodes.Status502BadGateway;
                app.Logger.LogWarning(ex, "Four-party federation to {AccessServer} failed.", resourceAudience);
                entry.Status = FederatedPendingStatus.Denied;
            }
            finally
            {
                entry.FirstAnswer.TrySetResult();
            }
        });

        // Wait for the first answer: either the AS asked for interaction
        // (relay it) or federation finished before any interaction.
        await entry.FirstAnswer.Task;

        if (entry.InteractionUrl is not null)
        {
            // Relay the AS interaction. The user logs in at the AS's
            // (Keycloak-backed) URL; the agent polls the PS pending URL while
            // the PS's background task polls the AS to completion.
            ctx.Response.Headers.Location = $"/federated-pending/{entry.Id}";
            ctx.Response.Headers["Retry-After"] = "1";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                Interaction.Format(entry.InteractionUrl, entry.InteractionCode!);
            return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
        }

        // The AS resolved without interaction (e.g. an auto-allow stub AS).
        if (entry.Status == FederatedPendingStatus.Allowed)
        {
            return Results.Ok(new { auth_token = entry.AuthToken });
        }

        if (!string.IsNullOrEmpty(entry.ErrorLocation))
        {
            ctx.Response.Headers.Location = entry.ErrorLocation;
        }
        return Results.Json(
            new { error = entry.Error, detail = entry.Error },
            statusCode: entry.ErrorStatus);
    }

    // Call-chaining: validate upstream_token if present using UpstreamTokenValidator
    // (§Upstream Token Verification steps 1-4).
    JsonObject? upstreamAct = null;
    if (!string.IsNullOrEmpty(upstreamTokenJwt))
    {
        var validator = app.Services.GetRequiredService<UpstreamTokenValidator>();
        // For this mock PS, trust all issuers. Production would maintain
        // a set of known ASes whose tokens the PS has previously brokered.
        var trustedIssuers = new HashSet<string> { psIssuer };

        // §Upstream Token Verification step 3: aud must match the intermediary
        // resource. Per §Call Chaining Identity, the intermediary self-issues
        // its agent token (iss = its resource URL). So agent_token.iss IS the
        // intermediary's resource identifier.
        var intermediaryResourceUrl = (string?)parsed.Payload?["iss"]
            ?? throw new InvalidOperationException("Agent token missing 'iss' claim.");

        var result = await validator.ValidateAsync(
            upstreamTokenJwt,
            expectedAudience: intermediaryResourceUrl,
            trustedIssuers);

        if (!result.IsValid)
        {
            return Results.Json(new { error = "invalid_upstream_token", detail = result.Error },
                statusCode: StatusCodes.Status400BadRequest);
        }

        // The result contains the fully nested act (intermediary wrapping upstream).
        upstreamAct = result.UpstreamAct;
    }

    // Verify the resource token per §"Resource Token Verification" before we
    // act on any of its claims. The SDK helper resolves the issuing resource's
    // JWKS from `{iss}/.well-known/aauth-resource.json` and enforces typ/dwk/
    // signature/exp/iat/aud (steps 1-4) plus agent + agent_jkt (steps 5-6).
    // The verified `iss` is the resource URL and becomes the auth token's
    // `aud`; the verified `scope` is echoed into the issued auth token.
    var tokenVerifier = app.Services.GetRequiredService<TokenVerifier>();
    var metadataClient = app.Services.GetRequiredService<MetadataClient>();
    var jwksClient = app.Services.GetRequiredService<JwksClient>();
    string audience;
    string requestedScope = PsScope;
    MissionClaim? missionClaim = null;
    try
    {
        var verifiedResourceToken = await tokenVerifier.VerifyResourceTokenAsync(
            resourceTokenJwt,
            expectedAudience: psIssuer,
            expectedAgentId: agentId,
            expectedAgentJkt: parsed.ConfirmationKey!.ComputeJwkThumbprint(),
            metadataClient,
            jwksClient);

        audience = (string?)verifiedResourceToken.Payload["iss"]
            ?? throw new TokenVerificationException("resource_token missing iss");
        // Echo the requested scope (space-separated set permitted). Fall back
        // to the PS's base scope when the resource token omits it.
        var scopeClaim = (string?)verifiedResourceToken.Payload["scope"];
        if (!string.IsNullOrWhiteSpace(scopeClaim))
        {
            requestedScope = scopeClaim;
        }
        // §Agent Token Request: the mission context (if any) rides the resource
        // token's `mission` claim. It governs the token gate below.
        missionClaim = MissionClaim.FromPayload(verifiedResourceToken.Payload);
    }
    catch (TokenVerificationException ex)
    {
        // §Error Response Format: a resource token that fails verification is
        // rejected outright — the consent screen and issued auth token derive
        // only from a verified token.
        var expired = ex.Message.Contains("expired", StringComparison.OrdinalIgnoreCase);
        return Results.Json(
            new
            {
                error = expired ? "expired_resource_token" : "invalid_resource_token",
                detail = ex.Message,
            },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // Mission gate (§Agent Token Request, three-gate model). When the resource
    // token carries a mission claim, the token request is governed by the
    // mission: silent when the (resource, scope) is within the approved intent
    // (gate 2a) or already consented earlier in this mission (gate 2b),
    // otherwise the user is prompted; a terminated mission is rejected outright.
    // Each outcome is recorded in the mission log so the reason is auditable.
    if (missionClaim is not null)
    {
        var missionStore = app.Services.GetRequiredService<IMissionStore>();
        var missionLog = app.Services.GetRequiredService<IMissionLog>();
        var missionPolicy = app.Services.GetRequiredService<MissionPolicyStore>();
        var missionPending = app.Services.GetRequiredService<MissionPendingStore>();
        var script = app.Services.GetRequiredService<MissionConsentScript>();
        var s256 = missionClaim.S256;

        var stored = await missionStore.GetAsync(s256);
        if (stored is { State: MissionState.Terminated })
        {
            return GovernanceEndpoints.MissionTerminated();
        }

        var inScope = missionPolicy.IsInScope(s256, audience, requestedScope);
        var priorConsent = !inScope
            && await missionLog.HasPriorConsentAsync(s256, audience, requestedScope);

        if (inScope || priorConsent)
        {
            await missionLog.AppendAsync(new MissionLogEntry(
                s256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
            {
                Resource = audience,
                Scope = requestedScope,
                Granted = true,
                Detail = inScope ? "InScope" : "PriorConsent",
            });
            var silentToken = IssueAuthToken(
                agentId, audience, requestedScope, parsed.ConfirmationKey!, upstreamAct, missionClaim);
            return Results.Ok(new { auth_token = silentToken });
        }

        // Out of scope -> park the request and prompt the user (§User Interaction).
        // The agent polls the pending URL while the (scripted) user decides; a
        // clarification chat runs first when the script requests one.
        var entry = missionPending.Add(new MissionPendingEntry
        {
            Kind = MissionPendingKind.Token,
            AgentId = agentId,
            S256 = s256,
            Approver = missionClaim.Approver,
            Resource = audience,
            Scope = requestedScope,
            ConfirmationKey = parsed.ConfirmationKey!,
            UpstreamAct = upstreamAct,
            Question = script.RequireTokenClarification ? script.ClarificationQuestion : null,
            State = script.RequireTokenClarification
                ? MissionPendingState.AwaitingClarification
                : MissionPendingState.AwaitingDecision,
        });

        ctx.Response.Headers.Location = $"/mission-pending/{entry.Id}";
        ctx.Response.Headers["Retry-After"] = "0";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        if (script.RequireTokenClarification)
        {
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                $"requirement={ClarificationRequirement.RequirementType}";
            return Results.Json(
                new { clarification = script.ClarificationQuestion },
                statusCode: StatusCodes.Status202Accepted);
        }

        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", entry.Id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // Consent gate. If the PS is configured to require consent and the
    // (agent, resource, scope) triple hasn't been approved yet, park the
    // request and tell the agent to direct its user to the interaction
    // endpoint while polling the pending URL.
    if (requireConsent && !consent.IsConsented(agentId, audience, requestedScope))
    {
        var entry = pending.Add(agentId, audience, requestedScope, resourceTokenJwt, parsed.ConfirmationKey!, upstreamAct);
        var location = $"/pending/{entry.Id}";
        var interactionUrl = $"{psIssuer.TrimEnd('/')}/interaction";
        ctx.Response.Headers.Location = location;
        ctx.Response.Headers["Retry-After"] = "0";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            Interaction.Format(interactionUrl, entry.Id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    var authToken = IssueAuthToken(agentId, audience, requestedScope, parsed.ConfirmationKey!, upstreamAct);
    return Results.Ok(new { auth_token = authToken });
});

// -----------------------------------------------------------------------
// GET /pending/{id} — the agent polls here while the user (allegedly)
// goes off and approves the request at the interaction endpoint. Signed,
// just like /token. Returns:
//   * 202 + same AAuth-Requirement header while pending (no consent yet)
//   * 200 + { auth_token } once consent has been recorded
//   * 404 if the pending id doesn't exist (e.g. already resolved + GC'd)
// -----------------------------------------------------------------------
app.MapGet("/pending/{id}", (HttpContext ctx, string id, ConsentStore consent, PendingStore pending) =>
{
    var entry = pending.Get(id);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }

    // Explicit denial — return 403 denied so the agent can
    // distinguish "user said no" from "timed out / unknown id".
    if (entry.Denied)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        return Results.Json(
            new { error = "denied", detail = "the user denied this request" },
            statusCode: StatusCodes.Status403Forbidden);
    }

    if (!consent.IsConsented(entry.Agent, entry.Resource, entry.Scope))
    {
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // Consent was recorded — mint the auth token bound to the same agent
    // confirmation key captured when the pending entry was created. We
    // intentionally leave the entry in place so a slow poller still gets
    // a deterministic answer on its next request; a production PS would
    // expire pending entries on a timer.
    var authToken = IssueAuthToken(entry.Agent, entry.Resource, entry.Scope, entry.AgentConfirmationKey, entry.UpstreamAct);
    return Results.Ok(new { auth_token = authToken });
});

// -----------------------------------------------------------------------
// GET /federated-pending/{id} — four-party deferred poll. Signed like
// /token. While the PS's background FederateAsync drives the AS interaction
// to completion, returns 202 + the relayed AS interaction requirement. Once
// federation resolves it returns the AS-issued auth token (200) or the
// relayed AS error (403 denied / 402 / 502).
// -----------------------------------------------------------------------
app.MapGet("/federated-pending/{id}", (HttpContext ctx, string id, FederatedPendingStore fedPending) =>
{
    var entry = fedPending.Get(id);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }

    switch (entry.Status)
    {
        case FederatedPendingStatus.Allowed:
            return Results.Ok(new { auth_token = entry.AuthToken });
        case FederatedPendingStatus.Denied:
            ctx.Response.Headers["Cache-Control"] = "no-store";
            if (!string.IsNullOrEmpty(entry.ErrorLocation))
            {
                ctx.Response.Headers.Location = entry.ErrorLocation;
            }
            return Results.Json(
                new { error = entry.Error, detail = entry.Error },
                statusCode: entry.ErrorStatus);
        case FederatedPendingStatus.Pending:
        default:
            ctx.Response.Headers["Retry-After"] = "1";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            if (entry.InteractionUrl is not null)
            {
                ctx.Response.Headers[AAuthRequirementHeader.Name] =
                    Interaction.Format(entry.InteractionUrl, entry.InteractionCode!);
            }
            return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }
});

// -----------------------------------------------------------------------
// Mission governance endpoints (§PS Governance Endpoints). All four are
// behind AAuth verification (signed agent-token requests); they sit on
// distinct paths from the browser `/interaction` consent page so they are
// not excluded from verification. User decisions come from the scripted
// MissionConsentScript (the mock's stand-in for a consent screen).
// -----------------------------------------------------------------------

// mission_endpoint (§Mission Creation): the agent proposes a mission; the PS
// records the approved mission and returns the verbatim approval blob plus the
// `AAuth-Mission` header whose `s256` the agent verifies.
app.MapPost("/mission", async (
    HttpContext ctx,
    IMissionStore missions,
    MissionPolicyStore policy,
    MissionConsentScript script,
    MissionPendingStore pending) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;
    if (ctx.GetAAuthTokenType() != AAuthTokenType.AgentToken)
    {
        return Results.Json(new { error = "invalid_carrier_token" }, statusCode: StatusCodes.Status401Unauthorized);
    }
    var agentId = (string?)parsed.Payload?["sub"];
    if (string.IsNullOrEmpty(agentId))
    {
        return Results.Json(new { error = "invalid_carrier_token", detail = "missing sub" }, statusCode: StatusCodes.Status401Unauthorized);
    }

    JsonObject? body;
    try
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }
    if (body is null)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    MissionProposal proposal;
    try
    {
        proposal = GovernanceEndpoints.ParseMissionProposal(body);
    }
    catch (FormatException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (!script.ApproveMissionProposal)
    {
        return Results.Json(new { error = "denied" }, statusCode: StatusCodes.Status403Forbidden);
    }

    // Interactive mode (§Mission Creation): mission approval is the most
    // important consent in the model, so park the proposal and let the user
    // approve it on the PS browser screen — the same deferred (202) path the
    // token and permission gates use. The agent's MissionClient polls the
    // pending URL and receives the signed approval blob once the user decides.
    if (script.InteractiveBrowser)
    {
        var pendingMission = pending.Add(new MissionPendingEntry
        {
            Kind = MissionPendingKind.Mission,
            AgentId = agentId,
            S256 = string.Empty,            // computed from the blob once approved
            Approver = psIssuer,
            Proposal = proposal,
        });
        ctx.Response.Headers.Location = $"/mission-create-pending/{pendingMission.Id}";
        ctx.Response.Headers["Retry-After"] = "0";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", pendingMission.Id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // The demo approves every proposed tool; a real PS would let the user prune them.
    var approvedTools = proposal.Tools;
    var (blob, s256) = MissionApprovalBuilder.Build(psIssuer, agentId, proposal, approvedTools, DateTimeOffset.UtcNow);

    await missions.SaveAsync(new StoredMission(s256, psIssuer, agentId, blob));
    policy.Record(s256, proposal.Description, approvedTools, script.InScopeSnapshot());

    ctx.Response.Headers[AAuthMissionHeader.Name] =
        AAuthMissionHeader.FormatStructured(psIssuer, s256);
    return Results.Bytes(blob, "application/json");
});

// Interactive mission-creation resolution (§Mission Creation). The agent polls
// here while the user approves or declines the proposed mission in the browser.
// On approval the PS builds and stores the verbatim approval blob and returns it
// with the AAuth-Mission header — exactly what the synchronous path returns.
app.MapGet("/mission-create-pending/{id}", async (
    HttpContext ctx, string id, MissionPendingStore pending,
    IMissionStore missions, MissionPolicyStore policy, MissionConsentScript script) =>
{
    var entry = pending.Get(id);
    if (entry is null || entry.Kind != MissionPendingKind.Mission)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }

    // Hold at 202 until the user decides on the browser consent screen.
    if (entry.Decision is null)
    {
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", entry.Id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    pending.Remove(id);
    if (!entry.Decision.Value)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        return Results.Json(
            new { error = "denied", detail = "the user declined this mission" },
            statusCode: StatusCodes.Status403Forbidden);
    }

    var proposal = entry.Proposal!;
    // The demo approves every proposed tool; a real PS would let the user prune them.
    var approvedTools = proposal.Tools;
    var (blob, s256) = MissionApprovalBuilder.Build(psIssuer, entry.AgentId, proposal, approvedTools, DateTimeOffset.UtcNow);
    await missions.SaveAsync(new StoredMission(s256, psIssuer, entry.AgentId, blob));
    policy.Record(s256, proposal.Description, approvedTools, script.InScopeSnapshot());
    ctx.Response.Headers[AAuthMissionHeader.Name] =
        AAuthMissionHeader.FormatStructured(psIssuer, s256);
    return Results.Bytes(blob, "application/json");
});

// permission_endpoint (§Permission Endpoint): the agent asks whether an action
// is permitted. A pre-approved tool is granted silently; anything else is parked
// (202) and resolved by the (scripted) user decision on the pending URL.
app.MapPost("/permission", async (
    HttpContext ctx,
    IMissionStore missions,
    IMissionLog log,
    IPermissionDecider decider,
    MissionConsentScript script,
    MissionPendingStore pending) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;
    var agentId = (string?)parsed.Payload?["sub"] ?? string.Empty;

    var body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    if (body is null)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    PermissionRequest request;
    try
    {
        request = GovernanceEndpoints.ParsePermission(body);
    }
    catch (FormatException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    StoredMission? stored = null;
    IReadOnlyList<MissionLogEntry> history = [];
    if (request.Mission is not null)
    {
        stored = await missions.GetAsync(request.Mission.S256);
        if (stored is { State: MissionState.Terminated })
        {
            return GovernanceEndpoints.MissionTerminated();
        }
        history = await log.ReadAsync(request.Mission.S256);
    }

    var decision = await decider.DecideAsync(new PermissionDecisionContext(request, stored, history));

    // Prompt -> park the request and let the agent poll while the user decides.
    if (decision.Outcome == PermissionOutcome.Prompt && request.Mission is not null)
    {
        var entry = pending.Add(new MissionPendingEntry
        {
            Kind = MissionPendingKind.Permission,
            AgentId = agentId,
            S256 = request.Mission.S256,
            Approver = request.Mission.Approver,
            Action = request.Action.Name,
        });
        ctx.Response.Headers.Location = $"/permission-pending/{entry.Id}";
        ctx.Response.Headers["Retry-After"] = "0";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        // Interactive mode points the user at the PS browser page to decide.
        if (script.InteractiveBrowser)
        {
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", entry.Id);
        }
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    var granted = decision.Outcome == PermissionOutcome.Granted;
    if (request.Mission is not null)
    {
        await log.AppendAsync(new MissionLogEntry(
            request.Mission.S256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
        {
            Action = request.Action.Name,
            Granted = granted,
            Detail = decision.Reason.ToString(),
        });
    }

    return Results.Json(new
    {
        permission = granted ? "granted" : "denied",
        reason = decision.Message ?? decision.Reason.ToString(),
    });
});

// audit_endpoint (§Audit Endpoint): the agent reports an action it took.
app.MapPost("/audit", async (
    HttpContext ctx,
    IMissionStore missions,
    IAuditSink sink) =>
{
    var body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    if (body is null)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    AuditRecord record;
    try
    {
        record = GovernanceEndpoints.ParseAudit(body);
    }
    catch (FormatException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    var stored = await missions.GetAsync(record.Mission.S256);
    if (stored is { State: MissionState.Terminated })
    {
        return GovernanceEndpoints.MissionTerminated();
    }

    await sink.RecordAsync(record);
    return Results.StatusCode(StatusCodes.Status201Created);
});

// interaction_endpoint (§Interaction Endpoint): questions and completion
// proposals relayed to the user. A completion the user accepts terminates the
// mission; otherwise the mission stays active.
app.MapPost("/mission-interaction", async (
    HttpContext ctx,
    IMissionStore missions,
    IMissionLog log,
    IInteractionRelay relay) =>
{
    var body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    if (body is null)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    InteractionRequest request;
    try
    {
        request = GovernanceEndpoints.ParseInteraction(body);
    }
    catch (FormatException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (request.Mission is not null)
    {
        var stored = await missions.GetAsync(request.Mission.S256);
        if (stored is { State: MissionState.Terminated })
        {
            return GovernanceEndpoints.MissionTerminated();
        }
    }

    var result = await relay.RelayAsync(request);

    if (request.Mission is not null)
    {
        await log.AppendAsync(new MissionLogEntry(
            request.Mission.S256, MissionLogEntryKind.Interaction, DateTimeOffset.UtcNow)
        {
            Detail = request.Type.ToString(),
        });
    }

    switch (request.Type)
    {
        case InteractionType.Question:
            return Results.Json(new { answer = result.Answer ?? string.Empty });

        case InteractionType.Completion:
            // The user accepted completion -> terminate the mission (§Mission Management).
            if (result.Accepted == true && request.Mission is not null)
            {
                await missions.SetStateAsync(request.Mission.S256, MissionState.Terminated);
                return Results.Json(new { mission_status = "terminated" });
            }
            return Results.Json(new { mission_status = "active" });

        default:
            return Results.Json(new { status = "ok" });
    }
});

// -----------------------------------------------------------------------
// Mission pending URLs. The agent polls (GET) for the user decision,
// answers a clarification (POST), or withdraws the request (DELETE). All
// signed like /token. The pending id is single-use and also the
// interaction code shown to the user.
// -----------------------------------------------------------------------

// Out-of-scope token resolution (§User Interaction / §Clarification Chat). The
// poll either runs a clarification round, resolves to an issued auth token, or
// reports the user's denial / the agent's withdrawal.
app.MapGet("/mission-pending/{id}", async (
    HttpContext ctx, string id, MissionPendingStore pending,
    IMissionLog log, MissionConsentScript script) =>
{
    var entry = pending.Get(id);
    if (entry is null || entry.Kind != MissionPendingKind.Token)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }

    switch (entry.State)
    {
        case MissionPendingState.Cancelled:
            ctx.Response.Headers["Cache-Control"] = "no-store";
            return Results.Json(new { error = "request_withdrawn" }, statusCode: StatusCodes.Status410Gone);

        case MissionPendingState.AwaitingClarification:
            ctx.Response.Headers["Retry-After"] = "0";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                $"requirement={ClarificationRequirement.RequirementType}";
            return Results.Json(
                new { clarification = entry.Question ?? script.ClarificationQuestion },
                statusCode: StatusCodes.Status202Accepted);

        case MissionPendingState.AwaitingDecision:
        default:
            // Interactive mode: hold at 202 until the user decides in the
            // browser (§User Interaction). Scripted mode resolves immediately.
            bool approved;
            if (script.InteractiveBrowser)
            {
                if (entry.Decision is null)
                {
                    ctx.Response.Headers["Retry-After"] = "1";
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    ctx.Response.Headers[AAuthRequirementHeader.Name] =
                        Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", entry.Id);
                    return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
                }
                approved = entry.Decision.Value;
            }
            else
            {
                approved = script.ApproveOutOfScopeToken;
            }
            await log.AppendAsync(new MissionLogEntry(
                entry.S256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
            {
                Resource = entry.Resource,
                Scope = entry.Scope,
                Granted = approved,
                Detail = "OutOfScope",
            });
            pending.Remove(id);
            if (!approved)
            {
                ctx.Response.Headers["Cache-Control"] = "no-store";
                return Results.Json(
                    new { error = "denied", detail = "the user denied this request" },
                    statusCode: StatusCodes.Status403Forbidden);
            }
            var token = IssueAuthToken(
                entry.AgentId, entry.Resource!, entry.Scope!, entry.ConfirmationKey!,
                entry.UpstreamAct, entry.MissionClaim);
            return Results.Ok(new { auth_token = token });
    }
});

// Clarification answer (`clarification_response`) or updated request
// (`resource_token`). Either satisfies the chat and readies the user decision.
app.MapPost("/mission-pending/{id}", async (
    HttpContext ctx, string id, MissionPendingStore pending, IMissionLog log) =>
{
    var entry = pending.Get(id);
    if (entry is null || entry.Kind != MissionPendingKind.Token)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }
    if (entry.State == MissionPendingState.Cancelled)
    {
        return Results.Json(new { error = "request_withdrawn" }, statusCode: StatusCodes.Status410Gone);
    }

    JsonObject? body;
    try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }
    var answer = (string?)body?["clarification_response"];
    await log.AppendAsync(new MissionLogEntry(
        entry.S256, MissionLogEntryKind.Clarification, DateTimeOffset.UtcNow)
    {
        Detail = answer ?? "updated_request",
    });
    entry.State = MissionPendingState.AwaitingDecision;
    return Results.NoContent();
});

// Withdraw the request (§Agent Response to Clarification — cancel). The DELETE
// succeeds (204); a later poll of the same URL returns 410 Gone.
app.MapDelete("/mission-pending/{id}", async (
    string id, MissionPendingStore pending, IMissionLog log) =>
{
    var entry = pending.Get(id);
    if (entry is null || entry.Kind != MissionPendingKind.Token)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }
    entry.State = MissionPendingState.Cancelled;
    await log.AppendAsync(new MissionLogEntry(
        entry.S256, MissionLogEntryKind.Clarification, DateTimeOffset.UtcNow)
    {
        Detail = "cancelled",
    });
    return Results.NoContent();
});

// Non-pre-approved permission resolution (§Permission Endpoint). The poll
// returns the (scripted) user decision.
app.MapGet("/permission-pending/{id}", async (
    HttpContext ctx, string id, MissionPendingStore pending,
    IMissionLog log, MissionConsentScript script) =>
{
    var entry = pending.Get(id);
    if (entry is null || entry.Kind != MissionPendingKind.Permission)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }
    // Interactive mode: hold at 202 until the user decides in the browser.
    bool granted;
    if (script.InteractiveBrowser)
    {
        if (entry.Decision is null)
        {
            ctx.Response.Headers["Retry-After"] = "1";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", entry.Id);
            return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
        }
        granted = entry.Decision.Value;
    }
    else
    {
        granted = script.ApprovePermission;
    }
    await log.AppendAsync(new MissionLogEntry(
        entry.S256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
    {
        Action = entry.Action,
        Granted = granted,
        Detail = "OutOfScope",
    });
    pending.Remove(id);
    return Results.Json(new
    {
        permission = granted ? "granted" : "denied",
        reason = granted ? "OutOfScope" : "the user denied this action.",
    });
});

// -----------------------------------------------------------------------
// DEMO-ONLY admin endpoints. A real PS would NEVER expose unauthenticated
// consent flips. These exist so the GuidedTour's "User approves" button
// and the §3.4 user-consent integration test can drive the consent
// transition deterministically. Body shape:
//   { "agent": "aauth:...@...", "resource": "https://whoami/", "scope": "whoami" }
// `scope` is optional and defaults to the PS's single demo scope.
// -----------------------------------------------------------------------
app.MapPost("/admin/consent", async (HttpContext ctx, ConsentStore consent) =>
{
    var (agent, resource, scope, err) = await ReadAdminBodyAsync(ctx);
    if (err is not null) { return err; }
    consent.Grant(agent!, resource!, scope!);
    return Results.Ok(new { ok = true, agent, resource, scope });
});

app.MapPost("/admin/revoke", async (HttpContext ctx, ConsentStore consent) =>
{
    var (agent, resource, scope, err) = await ReadAdminBodyAsync(ctx);
    if (err is not null) { return err; }
    consent.Revoke(agent!, resource!, scope!);
    return Results.Ok(new { ok = true, agent, resource, scope });
});

// Demo-only: wipe all consent + pending state back to baseline so an automated
// test harness can start each spec from a known-empty store (see the E2E suite's
// resetConsent helper). A production PS would never expose this.
app.MapPost("/admin/reset", (ConsentStore consent, PendingStore pending, FederatedPendingStore fedPending, MissionPendingStore missionPending, MissionConsentScript script) =>
{
    consent.Clear();
    pending.Clear();
    fedPending.Clear();
    missionPending.Clear();
    script.Reset();
    return Results.Ok(new { ok = true });
});

// DEMO-ONLY: script the next mission-governance decisions (option A). The
// CLI/E2E harness POSTs here before driving the agent so each Consent-Matrix
// outcome is reproducible. A real PS resolves these through a live user-consent
// screen. Body (all optional): { reset, approveMission, approveToken,
// approvePermission, questionAnswer, acceptCompletion, interactive,
// inScope: [{resource, scope}] }.
app.MapPost("/admin/mission-script", async (HttpContext ctx, MissionConsentScript script) =>
{
    JsonObject? body;
    try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }
    body ??= [];

    if ((bool?)body["reset"] == true) { script.Reset(); }
    if (body["approveMission"] is JsonValue am) { script.ApproveMissionProposal = am.GetValue<bool>(); }
    if (body["approveToken"] is JsonValue at) { script.ApproveOutOfScopeToken = at.GetValue<bool>(); }
    if (body["approvePermission"] is JsonValue ap) { script.ApprovePermission = ap.GetValue<bool>(); }
    if (body["questionAnswer"] is JsonValue qa) { script.QuestionAnswer = qa.GetValue<string>(); }
    if (body["acceptCompletion"] is JsonValue ac) { script.AcceptCompletion = ac.GetValue<bool>(); }
    if (body["requireClarification"] is JsonValue rc) { script.RequireTokenClarification = rc.GetValue<bool>(); }
    if (body["clarificationQuestion"] is JsonValue cq) { script.ClarificationQuestion = cq.GetValue<string>(); }
    if (body["interactive"] is JsonValue iv) { script.InteractiveBrowser = iv.GetValue<bool>(); }
    if (body["inScope"] is JsonArray inScope)
    {
        foreach (var item in inScope.OfType<JsonObject>())
        {
            var resource = (string?)item["resource"];
            var scope = (string?)item["scope"];
            if (!string.IsNullOrEmpty(resource) && !string.IsNullOrEmpty(scope))
            {
                script.SeedInScope(resource, scope);
            }
        }
    }
    return Results.Ok(new { ok = true });
});

// DEMO-ONLY: terminate a mission by its s256 (§Mission Management). After this
// the PS rejects token/permission/audit/interaction requests for the mission
// with `mission_terminated`. Body: { s256 }.
app.MapPost("/admin/mission-terminate", async (HttpContext ctx, IMissionStore missions, MissionPolicyStore policy) =>
{
    JsonObject? body;
    try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }
    var s256 = (string?)body?["s256"];
    if (string.IsNullOrEmpty(s256))
    {
        return Results.Json(new { error = "invalid_request", detail = "missing s256" }, statusCode: StatusCodes.Status400BadRequest);
    }
    await missions.SetStateAsync(s256, MissionState.Terminated);
    policy.Remove(s256);
    return Results.Ok(new { ok = true, s256, mission_status = "terminated" });
});

// DEMO-ONLY: read a mission's ordered log/trail by its s256 (§Mission Log). The
// PS holds the authoritative record of every governed step under the mission —
// tokens, permissions, clarifications, audits, interactions. Samples surface
// this to show the auditable trail a mission accrues. Returns { s256, entries:[…] }.
app.MapGet("/admin/mission-log/{s256}", async (string s256, IMissionLog log) =>
{
    var entries = await log.ReadAsync(s256);
    return Results.Ok(new
    {
        s256,
        entries = entries.Select(e => new
        {
            kind = e.Kind.ToString().ToLowerInvariant(),
            timestamp = e.Timestamp,
            resource = e.Resource,
            scope = e.Scope,
            action = e.Action,
            granted = e.Granted,
            detail = e.Detail,
        }).ToArray(),
    });
});

// User-facing interaction page. The 202 from `POST /token` told the
// agent's user to visit this URL with `?code={pending-id}`. In a real PS
// this page would be behind the user's signed-in browser session
// (cookie/passkey/SSO); here we trust the demo environment and just look
// up the pending entry by its single-use code. The form submits to
// /interaction/approve or /interaction/deny.
app.MapGet("/interaction", (string? code, PendingStore pending, MissionPendingStore missionPending, MissionPolicyStore missionPolicy) =>
{
    if (string.IsNullOrEmpty(code))
    {
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Mock PS consent</title>"
            + "<h1>Missing code</h1>"
            + "<p>This page must be visited with a <code>?code=…</code> query parameter from a pending AAuth interaction.</p>",
            contentType: "text/html",
            statusCode: StatusCodes.Status400BadRequest);
    }

    // A mission token / permission prompt (§Missions) takes priority — these
    // single-use codes are the mission-pending entry ids.
    var mission = missionPending.Get(code);
    if (mission is not null)
    {
        // Mission creation shows the proposal itself; the token/permission gates
        // show the request plus the mission it sits under (§Mission Creation).
        var isCreation = mission.Kind == MissionPendingKind.Mission;
        var description = isCreation ? mission.Proposal!.Description : missionPolicy.Describe(mission.S256);
        var approvedTools = isCreation
            ? (IReadOnlyCollection<string>)mission.Proposal!.Tools.Select(t => t.Name).ToArray()
            : missionPolicy.ApprovedTools(mission.S256);
        // Resource scopes (§Scopes) authorize access to a remote *resource* and
        // are carried in auth tokens; tools (§Permission Endpoint) are *local*
        // actions the agent runs itself. A mission proposal contains NO scopes —
        // the agent proposes only a description + tools, and the PS evaluates
        // each scope request lazily, per token request, over the mission's life
        // (§Mission Creation, §Scopes). So the creation screen lists no scopes;
        // the token/permission gates show the scopes consented so far.
        var inScopePairs = isCreation
            ? (IReadOnlyCollection<string>)Array.Empty<string>()
            : missionPolicy.InScopePairs(mission.S256);
        var what = mission.Kind switch
        {
            MissionPendingKind.Token =>
                "<div class=req><div class=req-h>This request</div>"
                + $"<div class=row><b>Resource:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.Resource)}</code></div>"
                + $"<div class=row><b>Scope:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.Scope)}</code></div>"
                + "<div class=req-n>Not yet covered by this mission — approve to grant this scope (the agent may reuse it for the rest of the mission).</div></div>",
            MissionPendingKind.Permission =>
                "<div class=req><div class=req-h>This request</div>"
                + $"<div class=row><b>Tool:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.Action)}</code></div>"
                + "<div class=req-n>A tool that is not pre-approved on the mission — approve to allow this call.</div></div>",
            _ => string.Empty,
        };
        // The mission claim binds requests to a thumbprint (s256); surface the
        // human-readable description the user approved so they can decide in
        // context, with the s256 shown only as a verifiable reference. At
        // creation time the s256 does not exist yet, so show only the prose.
        var missionLine = isCreation
            ? $"<div class=row><b>Mission:</b> <span>{System.Net.WebUtility.HtmlEncode(description)}</span></div>"
            : description is not null
                ? $"<div class=row><b>Mission:</b> <span>{System.Net.WebUtility.HtmlEncode(description)}</span></div>"
                  + $"<div class=row><b></b> <code style='font-size:.8rem;color:#888'>{System.Net.WebUtility.HtmlEncode(mission.S256)}</code></div>"
                : $"<div class=row><b>Mission:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.S256)}</code></div>";
        // Show the mission's resource scopes and pre-approved tools (§Scopes vs
        // §Permission Endpoint) so the user sees the authority this request sits
        // under. A mission proposal lists NO scopes, so at creation we show no
        // scope list — only a note that the PS will judge each scope request
        // against the mission as it arrives. On the token/permission gates the
        // user is here precisely BECAUSE this scope/tool is not yet covered
        // (gate 3, §Agent Token Request), so we show what has already been
        // granted this mission as context for the new decision — not as the
        // thing being requested now.
        var scopesLine = isCreation
            ? string.Empty
            : inScopePairs.Count > 0
                ? $"<div class=row><b>Granted&nbsp;so&nbsp;far:</b> <code>{System.Net.WebUtility.HtmlEncode(string.Join(", ", inScopePairs))}</code></div>"
                : "<div class=row><b>Granted&nbsp;so&nbsp;far:</b> <span style='color:#888'>nothing yet — this is the first request</span></div>";
        // At creation the agent proposed only a description + tools (§Mission
        // Creation) — it did NOT request scopes, and the PS does not enumerate
        // them up front. Tell the user the PS will determine the scopes the
        // mission needs from its description, request by request, as the agent
        // works (§Scopes — "The PS evaluates requested scopes against mission
        // context").
        var scopesNote = isCreation
            ? "<div class=req-n style='margin:.2rem 0 .4rem 0'>This mission grants no scopes up front. The Person Server will determine the resource scopes it needs from the mission description, judging each request as the agent makes it — granting silently if it fits the intent, or asking you otherwise.</div>"
            : string.Empty;
        var toolsLabel = isCreation ? "Tools" : "Approved&nbsp;tools";
        var toolsLine = approvedTools.Count > 0
            ? $"<div class=row><b>{toolsLabel}:</b> <code>{System.Net.WebUtility.HtmlEncode(string.Join(", ", approvedTools))}</code></div>"
            : $"<div class=row><b>{toolsLabel}:</b> <span style='color:#888'>(none)</span></div>";
        // A short, spec-grounded note defining the two kinds of authority so the
        // user understands what they are approving (§Scopes, §Permission Endpoint).
        var defn =
            "<div class=defn>"
            + "<div><b>Resource scope</b> — access to a remote <i>resource</i> (e.g. an API), granted via an auth token. "
            + "The resource defines its scopes; the Person Server determines which a mission needs from its intent.</div>"
            + "<div><b>Tool</b> — a <i>local</i> action the agent runs itself (a tool call, file write, message). "
            + "No resource is involved; the Person Server governs it through this permission step.</div>"
            + "</div>";
        var heading = isCreation
            ? "An agent wants to start a new mission"
            : $"An agent is requesting {(mission.Kind == MissionPendingKind.Token ? "access" : "permission")} under its mission";
        var intro = isCreation
            ? "The agent proposed a durable <b>mission</b> and the <b>tools</b> it wants to run. As the agent works, the Person Server will determine the resource <b>scopes</b> it needs from the mission description, judging each request in context. Approve to start the mission; every later request is checked against it."
            : "This request falls <b>outside</b> the agent's pre-approved mission scope, so the Person Server is asking you to decide.";
        var missionHtml =
            "<!doctype html><meta charset=utf-8><title>Approve a mission request — Person Server</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#7c3aed;color:#fff;"
            + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
            + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#ddd6fe}"
            + ".sub{color:#777;font-size:.85rem;margin:.35rem 0 1.25rem}"
            + "h1{font-size:1.25rem}.row{display:flex;gap:.5rem;margin:.25rem 0}.row b{min-width:7rem;color:#555}"
            + ".req{margin:1rem 0;padding:.6rem .85rem;background:#faf5ff;border:1px solid #e9d5ff;border-radius:.4rem}"
            + ".req-h{font-weight:600;color:#6b21a8;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;margin-bottom:.35rem}"
            + ".req-n{color:#777;font-size:.82rem;margin-top:.35rem}"
            + ".defn{margin:1.25rem 0 .5rem;padding:.6rem .85rem;background:#f8fafc;border:1px solid #e2e8f0;"
            + "border-radius:.4rem;font-size:.82rem;color:#555;display:flex;flex-direction:column;gap:.4rem}"
            + "form{margin-top:1.5rem;display:inline-flex;gap:.75rem}"
            + "button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;border-radius:.25rem;border:1px solid #999}"
            + "button.approve{background:#6ee7b7;border-color:#34d399}"
            + "button.deny{background:#fecaca;border-color:#f87171}</style>"
            + "<div class=badge><span class=dot></span>Person Server — mission governance</div>"
            + "<div class=sub>localhost:5100 — overseeing what this agent does under its mission</div>"
            + $"<h1>{heading}</h1>"
            + $"<p>{intro}</p>"
            + $"<div class=row><b>Agent:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.AgentId)}</code></div>"
            + missionLine
            + scopesLine
            + scopesNote
            + toolsLine
            + what
            + defn
            + "<form method=post action=\"/interaction/approve\">"
            + $"<input type=hidden name=code value=\"{System.Net.WebUtility.HtmlEncode(code)}\">"
            + "<button class=approve type=submit>Approve</button>"
            + "</form>"
            + "<form method=post action=\"/interaction/deny\">"
            + $"<input type=hidden name=code value=\"{System.Net.WebUtility.HtmlEncode(code)}\">"
            + "<button class=deny type=submit>Deny</button>"
            + "</form>";
        return Results.Content(missionHtml, contentType: "text/html");
    }

    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Mock PS consent</title>"
            + "<h1>Unknown or expired code</h1>"
            + "<p>This consent request is no longer pending. The agent may have already received an auth token, or the code was never issued.</p>",
            contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }

    var html =
        "<!doctype html><meta charset=utf-8><title>Approve agent at the Person Server</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#1d4ed8;color:#fff;"
        + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
        + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#bfdbfe}"
        + ".sub{color:#777;font-size:.85rem;margin:.35rem 0 1.25rem}"
        + "h1{font-size:1.25rem}.row{display:flex;gap:.5rem;margin:.25rem 0}.row b{min-width:6rem;color:#555}"
        + "form{margin-top:1.5rem;display:inline-flex;gap:.75rem}"
        + "button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;border-radius:.25rem;border:1px solid #999}"
        + "button.approve{background:#6ee7b7;border-color:#34d399}"
        + "button.deny{background:#fecaca;border-color:#f87171}</style>"
        + "<div class=badge><span class=dot></span>Person Server</div>"
        + "<div class=sub>localhost:5100 — the server that holds your resources and standing consent</div>"
        + "<h1>An agent is requesting access on your behalf</h1>"
        + "<p>This is the <b>Person Server's</b> consent screen. In a real PS you would be signed in via cookie / passkey / SSO before reaching here.</p>"
        + $"<div class=row><b>Agent:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.Agent)}</code></div>"
        + $"<div class=row><b>Resource:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.Resource)}</code></div>"
        + $"<div class=row><b>Scope:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.Scope)}</code></div>"
        + "<form method=post action=\"/interaction/approve\">"
        + $"<input type=hidden name=code value=\"{System.Net.WebUtility.HtmlEncode(code)}\">"
        + "<button class=approve type=submit>Approve</button>"
        + "</form>"
        + "<form method=post action=\"/interaction/deny\">"
        + $"<input type=hidden name=code value=\"{System.Net.WebUtility.HtmlEncode(code)}\">"
        + "<button class=deny type=submit>Deny</button>"
        + "</form>";
    return Results.Content(html, contentType: "text/html");
});

// Approve handler. Reads the pending id from the posted form, records
// consent for the entry's (agent, resource, scope) triple, and shows a
// confirmation page. Idempotent: re-submitting a code whose entry is
// already approved still 200s.
app.MapPost("/interaction/approve", async (HttpContext ctx, ConsentStore consent, PendingStore pending, MissionPendingStore missionPending) =>
{
    var code = (await ctx.Request.ReadFormAsync())["code"].ToString();
    if (string.IsNullOrEmpty(code))
    {
        return Results.BadRequest(new { error = "invalid_request", detail = "missing 'code'" });
    }
    // Mission token / permission prompt: record the user's approval so the
    // agent's next poll resolves to a granted decision (§Missions).
    var mission = missionPending.Get(code);
    if (mission is not null)
    {
        mission.Decision = true;
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Approved — Person Server</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#7c3aed;color:#fff;"
            + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
            + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#ddd6fe}</style>"
            + "<div class=badge><span class=dot></span>Person Server — mission governance</div>"
            + "<h1>Approved</h1>"
            + $"<p>You approved <code>{System.Net.WebUtility.HtmlEncode(mission.AgentId)}</code>'s mission request. The agent will proceed on its next poll.</p>"
            + "<p>You can close this tab.</p>",
            contentType: "text/html");
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_code", code });
    }
    consent.Grant(entry.Agent, entry.Resource, entry.Scope);
    return Results.Content(
        "<!doctype html><meta charset=utf-8><title>Approved — Person Server</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#1d4ed8;color:#fff;"
        + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
        + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#bfdbfe}</style>"
        + "<div class=badge><span class=dot></span>Person Server</div>"
        + "<h1>Approved</h1>"
        + $"<p>You granted <code>{System.Net.WebUtility.HtmlEncode(entry.Agent)}</code> access to "
        + $"<code>{System.Net.WebUtility.HtmlEncode(entry.Resource)}</code> with scope "
        + $"<code>{System.Net.WebUtility.HtmlEncode(entry.Scope)}</code> at the <b>Person Server</b>.</p>"
        + "<p>You can close this tab — the agent will receive its auth token on its next poll.</p>",
        contentType: "text/html");
}).DisableAntiforgery();

// Deny handler. Marks the pending entry as denied (rather than removing
// it) so the agent's next poll receives a deterministic
// `403 denied` instead of an ambiguous `404 unknown_pending`.
app.MapPost("/interaction/deny", async (HttpContext ctx, PendingStore pending, MissionPendingStore missionPending) =>
{
    var code = (await ctx.Request.ReadFormAsync())["code"].ToString();
    if (string.IsNullOrEmpty(code))
    {
        return Results.BadRequest(new { error = "invalid_request", detail = "missing 'code'" });
    }
    // Mission token / permission prompt: record the user's denial so the
    // agent's next poll resolves to a denied decision (§Missions).
    var mission = missionPending.Get(code);
    if (mission is not null)
    {
        mission.Decision = false;
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Denied — Person Server</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#7c3aed;color:#fff;"
            + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
            + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#ddd6fe}</style>"
            + "<div class=badge><span class=dot></span>Person Server — mission governance</div>"
            + "<h1>Denied</h1>"
            + $"<p>You denied <code>{System.Net.WebUtility.HtmlEncode(mission.AgentId)}</code>'s mission request. The agent's next poll will receive <code>403 denied</code>.</p>"
            + "<p>You can close this tab.</p>",
            contentType: "text/html");
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_code", code });
    }
    pending.Deny(code);
    return Results.Content(
        "<!doctype html><meta charset=utf-8><title>Denied — Person Server</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#1d4ed8;color:#fff;"
        + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
        + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#bfdbfe}</style>"
        + "<div class=badge><span class=dot></span>Person Server</div>"
        + "<h1>Denied</h1>"
        + $"<p>You denied <code>{System.Net.WebUtility.HtmlEncode(entry.Agent)}</code>'s request at the <b>Person Server</b>. The agent's next poll will receive <code>403 denied</code>.</p>"
        + "<p>You can close this tab.</p>",
        contentType: "text/html");
}).DisableAntiforgery();

app.Run();

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
string IssueAuthToken(string agentId, string audience, string scope, IAAuthKey confirmationKey, JsonObject? upstreamAct = null, MissionClaim? mission = null)
    => new AuthTokenBuilder
    {
        Issuer = psIssuer,
        Audience = audience,
        Agent = agentId,
        AgentConfirmationKey = confirmationKey,
        Key = psKey,
        KeyId = PsKid,
        Subject = "pairwise-sub",
        Scope = scope,
        Roles = IsAdminAgent(agentId) ? demoRoles : null,
        Groups = IsAdminAgent(agentId) ? demoGroups : null,
        UpstreamAct = upstreamAct,
        Mission = mission,
    }.Build();

// Peek the `aud` claim of a (possibly unverified) compact JWT without checking
// its signature — used only to ROUTE the request (three-party vs four-party).
// Whichever branch is taken fully verifies the token afterwards, so an attacker
// gains nothing by lying about `aud` here.
static string? PeekJwtAudience(string jwt)
{
    var parts = jwt.Split('.');
    if (parts.Length < 2)
    {
        return null;
    }
    JsonObject? payload;
    try
    {
        payload = JsonNode.Parse(Base64UrlDecode(parts[1])) as JsonObject;
    }
    catch (System.Text.Json.JsonException)
    {
        return null;
    }
    return payload?["aud"] switch
    {
        JsonValue v => v.GetValue<string>(),
        JsonArray { Count: > 0 } a => (string?)a[0],
        _ => null,
    };
}

static string Base64UrlDecode(string segment)
{
    var s = segment.Replace('-', '+').Replace('_', '/');
    s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => string.Empty };
    return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(s));
}

async Task<(string? Agent, string? Resource, string? Scope, IResult? Error)> ReadAdminBodyAsync(HttpContext ctx)
{
    JsonObject? body;
    try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
    catch (System.Text.Json.JsonException)
    {
        return (null, null, null, Results.Json(
            new { error = "invalid_request", detail = "body is not valid JSON" },
            statusCode: StatusCodes.Status400BadRequest));
    }

    var agent = (string?)body?["agent"];
    var resource = (string?)body?["resource"];
    var scope = (string?)body?["scope"] ?? PsScope;
    if (string.IsNullOrEmpty(agent) || string.IsNullOrEmpty(resource))
    {
        return (null, null, null, Results.Json(
            new { error = "invalid_request", detail = "missing 'agent' or 'resource'" },
            statusCode: StatusCodes.Status400BadRequest));
    }
    return (agent, resource, scope, null);
}

// Marker type for `WebApplicationFactory<MockPersonServer.Entry>` in the
// integration tests. We don't expose `public partial class Program;` here
// because the WhoAmI sample already declares its own global `Program`, and
// adding both project references to a test assembly would make `Program`
// ambiguous. A dedicated, namespaced marker sidesteps that.
namespace MockPersonServer
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}

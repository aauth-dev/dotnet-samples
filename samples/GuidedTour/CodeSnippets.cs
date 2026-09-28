namespace GuidedTour;

/// <summary>
/// SDK code snippets shown in the right panel for each tour step.
/// Aligned with the examples in /docs.
/// </summary>
internal static class CodeSnippets
{
    public const string GenerateKey = """
        var key = AAuthKey.Generate(); // Ed25519
        var publicJwk = key.ToPublicJwk();
        var thumbprint = key.ComputeJwkThumbprint();
        """;

    public const string SelfSignAgentToken = """
        var agentToken = new AgentTokenBuilder
        {
            EgressPolicy = SampleEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:myapp@ap.example",
            KeyId = "sample-key-1",
            Key = key,
            PersonServer = "https://ps.example",
        }.Build();
        """;

    public const string DiscoverAp = """
        // AP metadata: GET /.well-known/aauth-agent.json
        var metadata = new MetadataClient(policy: SampleEgress.Policy);
        var meta = await metadata.FetchAsync(
            metadata.GetUrl("https://ap.example", "aauth-agent.json"));
        var enrolEndpoint = (string)meta["enrol_endpoint"];
        """;

    public const string EnrolWithAp = """
        var keyStore = FileKeyStore.Default();
        var key = keyStore.LoadOrCreate("myapp");
        var result = await AAuthClientBuilder.Bootstrap("https://ap.example/enrol")
            .WithEgressPolicy(SampleEgress.Policy)
            .WithKey(key)
            .WithKeyStore(keyStore)
            .WithPersonServer("https://ps.example")
            .EnrolAsync();

        // result.Key             — Ed25519 signing key
        // result.AgentToken      — aa-agent+jwt from the AP
        // result.LocalKeyHandle  — agent-local IKeyStore handle (defaults to the durable key's JWK thumbprint)
        // result.AgentTokenKid   - AP-published kid (direct jwks demonstration)
        // result.JwksUri         — per-agent JWKS endpoint
        """;

    public const string DiscoverResource = """
        // Resource metadata: GET /.well-known/aauth-resource.json
        var metadata = new MetadataClient(policy: SampleEgress.Policy);
        var meta = await metadata.FetchAsync(
            metadata.GetUrl("https://resource.example", "aauth-resource.json"));
        """;

    public const string SignedGetHwk = """
        using var client = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy)
            .UseHwk()
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<public-key>";alg="Ed25519"
        """;

    public const string SignedGetJwksUri = """
        // kid must match the AP's published JWKS entry.
        // The AP returns this as key_id at enrollment — there is no valid fallback.
        var kid = result.AgentTokenKid
            ?? throw new InvalidOperationException("AP did not return key_id for direct jwks mode.");
        using var client = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy)
            .UseJwks(result.JwksUri!, kid)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=jwks;url="<jwks-url>";kid="<kid>"
        """;

    public const string SignedGetJwt = """
        using var client = AAuthClientBuilder.Enrolled(key).WithEgressPolicy(SampleEgress.Policy)
            .RefreshingFrom(refreshEndpoint, localKeyHandle)
            .WithKeyStore(keyStore)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=jwt;jwt="<aa-agent+jwt>"
        """;

    public const string SignedGetJktJwt = """
        // jkt-jwt mode: the durable key signs a self-issued naming JWT that
        // embeds its own public key in the header and binds the ephemeral
        // signing key via cnf.jwk. The ephemeral key signs the HTTP request.
        // Supports key rotation without re-enrolment.
        //
        // Self-anchored (Signature Keys draft-08 section 3.5): the verifier computes the durable
        // key's thumbprint from the header jwk, checks it equals iss
        // (urn:jkt:sha-256:<thumbprint>), then verifies the naming JWT signature.
        var namingJwt = NamingJwtBuilder.Build(durableKey, ephemeralKey);

        using var client = new AAuthClientBuilder(ephemeralKey).WithEgressPolicy(SampleEgress.Policy)
            .UseJktJwt(() => namingJwt)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=jkt-jwt;jwt="<jkt-s256+jwt>"
        """;

    public const string ParseChallenge = """
        // Parse the 401's AAuth-Requirement: requirement=auth-token header
        var header = response.Headers
            .GetValues("AAuth-Requirement").First();
        var requirement = AAuthRequirementHeader.Parse(header);
        var resourceToken = requirement.ResourceToken;
        // aa-resource+jwt: aud = PS (three-party) or AS (four-party); ps + sub name
        // the person; presented_jti names the token presented; agent_jkt the key.
        """;

    public const string DiscoverPs = """
        // PS metadata: GET /.well-known/aauth-person.json
        var metadata = new MetadataClient(policy: SampleEgress.Policy);
        var meta = await metadata.FetchAsync(
            metadata.GetUrl("https://ps.example", "aauth-person.json"));
        var personTokenEndpoint = (string)meta["person_token_endpoint"];
        var tokenEndpoint = (string)meta["auth_token_endpoint"];
        """;

    public const string RequestPersonToken = """
        // POST {person_token_endpoint} { resource }, signed with the agent token.
        var exchange = new TokenExchangeClient(signedClient, metadata);
        var personToken = await exchange.RequestPersonTokenAsync(
            "https://ps.example", "https://resource.example");
        // aa-person+jwt: aud = resource, directed sub, cnf = agent key; no scope.
        """;

    public const string PresentPersonToken = """
        // Present the person token in place of the agent token.
        using var personClient = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy)
            .UseJwt(personToken)
            .Build();
        var challenge = await personClient.GetAsync("https://resource.example/data");
        // 401 AAuth-Requirement: requirement=auth-token; resource-token="..."
        """;

    public const string TokenExchangeDirect = """
        // Automatic (recommended): the challenge handler requests the person
        // token, presents it, exchanges the resource token and retries.
        using var client = AAuthClientBuilder.Enrolled(key).WithEgressPolicy(SampleEgress.Policy)
            .RefreshingFrom(refreshEndpoint, localKeyHandle)
            .WithKeyStore(keyStore)
            .WithChallengeHandling(personServer: "https://ps.example")
            .Build();

        // Or manual: send the resource token with the token presented to the resource.
        var exchange = new TokenExchangeClient(signedClient, metadata);
        var authToken = await exchange.ExchangeAsync(
            "https://ps.example", resourceToken, presentedToken: personToken);
        """;

    public const string TokenExchangeDeferred = """
        var exchange = new TokenExchangeClient(signedClient, metadata);
        var authToken = await exchange.ExchangeAsync(
            "https://ps.example",
            resourceToken,
            new TokenExchangeRequest
            {
                PresentedToken = personToken,
                OnInteractionRequired = (interaction, ct) =>
                {
                    Console.WriteLine($"Approve at: {interaction.BuildUserUrl()}");
                    return Task.CompletedTask;
                },
                PollerOptions = new DeferredPollerOptions
                {
                    MaxTotalWait = TimeSpan.FromMinutes(5),
                },
            });
        """;

    public const string DirectUserToInteraction = """
        // The SDK provides the interaction URL + code:
        var userUrl = interaction.BuildUserUrl();
        // → "https://ps.example/interaction?code=ABCD1234"

        // Present to user via browser, QR code, notification, etc.
        Process.Start(new ProcessStartInfo(userUrl)
            { UseShellExecute = true });
        """;

    public const string PollPending = """
        var poller = new DeferredPoller(signedClient,
            new DeferredPollerOptions
            {
                MaxTotalWait = TimeSpan.FromMinutes(5),
                DefaultPollInterval = TimeSpan.FromSeconds(2),
                // Long-poll: server can hold the connection open (RFC 7240)
                PreferWaitSeconds = 30,
            });

        var result = await poller.PollAsync(pendingUri);
        var authToken = (string)JsonNode.Parse(
            await result.Content.ReadAsStringAsync())!["auth_token"]!;
        """;

    public const string ReplayWithAuthToken = """
        // The ChallengeHandler does this automatically when you use
        // WithTokenRefresh + WithChallengeHandling.
        // The SDK signs the retry with the auth_token internally.

        var response = await client.GetAsync("https://resource.example/data");
        // Now signed with the auth_token → 200 OK
        """;

    public const string R3AccountRequest = """
        // Present the person token; the resource token echoes the account.
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"{bookings}/search_availability?account={Uri.EscapeDataString(account)}");
        request.Options.Set(AAuthRequestOptions.Account, account);
        var challenge = await client.SendAsync(request);
        var auth = await exchange.ExchangeAsync(personServer, resourceToken,
            new TokenExchangeRequest { Account = account, PresentedToken = personToken });
        // Account must match the resource token, auth token and R3 document;
        // the person token itself never carries an account.
        """;

    public const string R3ConfirmConditional = """
        // Rich Resource Requests (R3): the client is the ordinary four-party
        // self-issued agent — the R3 detail rides the tokens, not the client.
        // A CONDITIONAL operation (confirmReservation charges a deposit) can't
        // be served outright; the resource replies 401 with a per-call PROPOSAL
        // carrying the concrete parameters, and the R3 Access Server asks the
        // user to approve that specific booking (202 → consent → poll → mint).
        using var client = AAuthClientBuilder.SelfIssuing(key).WithEgressPolicy(SampleEgress.Policy)
            .As(issuer, agentId)
            .WithKid(keyId)
            .WithPersonServer(personServer)
            .WithChallengeHandling(opts =>
            {
                opts.OnInteractionRequired = (interaction, ct) =>
                {
                    var url = interaction.BuildUserUrl(); // R3 AS consent link
                    // Surface url to the user, then the SDK polls.
                    return Task.CompletedTask;
                };
            })
            .Build();

        // The SAME parameters are resent on the approved retry and must match
        // the proposal's digest (r3 §Per-Call Proposals).
        var reservation = new
        {
            reservation_id = "dining-lumiere-001",
            venue = "Le Lumière (dinner for 2)",
            date = "2026-07-14T19:30",
            party_size = 2,
            deposit_usd = 40,
            cancellation_policy = "Deposit refundable up to 48 hours before the reservation.",
        };
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"{bookings}/confirm_reservation?account={Uri.EscapeDataString(account)}")
            { Content = JsonContent.Create(reservation) };
        request.Options.Set(AAuthRequestOptions.Account, account);
        var confirm = await client.SendAsync(request);
        """;

    public const string ResourceManagedSignedGet = """
        // Two-party resource-managed access (§AAuth-Access Response Header):
        // the resource manages authorization ITSELF — no Person Server, no
        // token exchange. WithResourceManagedAccess() captures the opaque
        // AAuth-Access token and replays it; WithInteractionHandling() drives
        // the 202 → consent → poll → 200 handshake.
        // GuidedTour is its own AP: its injected SelfIssuedIdentity publishes
        // this issuer and key. Provisioning is local, not external enrollment.
        using var client = AAuthClientBuilder.SelfIssuing(_selfIdentity.Key)
            .WithEgressPolicy(SampleEgress.Policy)
            .As(_selfIdentity.Issuer, _options.AgentId)
            .WithKid(_selfIdentity.KeyId)
            .WithResourceManagedAccess()
            .WithInteractionHandling(o =>
            {
                o.OnInteractionRequired = (url, code, ct) =>
                {
                    Console.WriteLine($"Approve at: {url}");
                    return Task.CompletedTask;
                };
            })
            .Build();

        // First call: 202 + AAuth-Requirement: requirement=interaction.
        // Agent JWT + HTTP proof, then opaque AAuth-Access after Inbox consent.
        // The walkthrough sends each request separately to expose these steps.
        var response = await client.GetAsync("https://inbox.example/messages");
        """;

    public const string ResourceManagedPoll = """
        // While the user approves on the Inbox's own consent page, the SDK
        // polls the pending URL (signed). Once consent is recorded the Inbox
        // replies 200 + AAuth-Access: <token68> — an opaque token bound to the
        // agent's signature (useless as a standalone bearer token).
        var poller = new DeferredPoller(signedClient,
            new DeferredPollerOptions { PreferWaitSeconds = 30 });

        var result = await poller.PollAsync(pendingUri);
        var token68 = result.Headers
            .GetValues("AAuth-Access").Single();
        // WithResourceManagedAccess retains the origin/key/account-bound credential.
        """;

    public const string ResourceManagedReplay = """
        // Later calls present the opaque token as an Authorization credential.
        // The signer automatically COVERS `authorization`, binding the token to
        // this request — so a stolen token cannot be replayed without the key.
        using var req = new HttpRequestMessage(
            HttpMethod.Get, "https://inbox.example/messages");
        req.Headers.Authorization =
            new AuthenticationHeaderValue("AAuth", token68);

        var response = await client.SendAsync(req); // signed + covered
        // 200 → { scope, messages }
        // (WithResourceManagedAccess() does this replay for you.)
        """;

    public const string CallChainRetry = """
        // Retry Concierge with the auth_token.
        // From our side this looks like a normal retry — the chaining
        // happens server-side inside the Concierge:
        //   1. Concierge validates our auth_token
        //   2. Requests a Calendar person token with it as upstream_token
        //   3. Presents that person token to Calendar → resource token
        //   4. Exchanges at the PS with presented_token + upstream_token
        //   5. Retries Calendar with the auth token (same ps, directed sub) → 200
        using var chainClient = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy)
            .UseJwt(authToken) // present the auth_token directly
            .Build();

        var response = await chainClient.GetAsync("https://concierge.example/");
        // 200 → combined result: upstream and downstream grants for the same ps
        """;

    public const string CallChainConvenience = """
        // Convenience: WithCallChaining routes the downstream person token and
        // auth token requests to the PS the upstream token names (its `ps`),
        // passing it as upstream_token; a mission_s256 in the upstream token
        // governs the downstream hop too.
        // The intermediary presents its own agent JWT in Signature-Key;
        // upstream_token is a body parameter, not a signing credential.
        // Cached grants are bound to the exact upstream authorization.
        // Use this when building an intermediary service:
        using var downstream = AAuthClientBuilder.SelfIssuing(myKey).WithEgressPolicy(SampleEgress.Policy)
            .As(myIssuer, myAgentId)
            .WithPersonServer(psUrl)
            .WithCallChaining(httpContext) // reads upstream token from request
            .Build();

        var result = await downstream.GetAsync("https://downstream.example/");
        // SDK handles: person token → challenge → exchange with upstream_token → retry
        """;

    public const string FullAutomatic = """
        // --- Provisioning (separate tool / CLI — run once per install) ---
        var keyStore = FileKeyStore.Default();
        var enrolResult = await AAuthClientBuilder
            .Bootstrap("https://ap.example/enrol")
            .WithKey(keyStore.LoadOrCreate("myapp"))
            .WithPersonServer("https://ps.example")
            .WithKeyStore(keyStore)
            .EnrolAsync();
        // Record enrolResult.LocalKeyHandle in app config — that's all you need

        // --- Application (every startup — load key by handle) ---
        var key = keyStore.Load(localKeyHandle);
        using var client = AAuthClientBuilder.Enrolled(key).WithEgressPolicy(SampleEgress.Policy)
            .RefreshingFrom(refreshEndpoint, localKeyHandle)
            .WithKeyStore(keyStore)
            .WithChallengeHandling("https://ps.example")
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // 401 person-token → person token → 401 resource token → exchange → poll → retry,
        // all handled transparently
        """;

    // ── Mission-governed flow (§Missions, §PS Governance Endpoints) ──────────

    public const string MissionDiscoverPs = """
        // GET /.well-known/aauth-person.json
        var metadata = new MetadataClient(policy: SampleEgress.Policy);
        var meta = await metadata.FetchAsync(
            metadata.GetUrl("https://ps.example", "aauth-person.json"));
        var mission     = (string)meta["mission_endpoint"];
        var personEp    = (string)meta["person_token_endpoint"];
        var tokenEp     = (string)meta["auth_token_endpoint"];
        var permission  = (string)meta["permission_endpoint"];
        """;

    public const string MissionPropose = """
        var governance = new AAuthGovernanceClient(
            signedClient, metadata, "https://ps.example");
        var session = await governance.ProposeMissionAsync(
            new MissionProposal("Plan my weekend trip to Seattle.")
            {
                Tools =
                [
                    new MissionTool("compare_options"),
                    new MissionTool("add_to_calendar"),
                ],
            },
            new GovernanceOptions { OnInteractionRequired = SurfaceToUser });
        var mission = session.Mission; // the session carries mission_s256 + the PS
        // SDK POSTs /mission → 202; SurfaceToUser shows the consent link,
        // then the client polls until the user approves.
        """;

    public const string MissionPollCreate = """
        // The MissionClient polls the mission-pending URL internally and returns
        // the parsed Mission once the user approves. The approval envelope is
        // { s256, mission }: mission is the approved JSON, s256 its SHA-256.
        var verified = mission.VerifyS256(s256); // integrity of the mission bytes
        // mission.PersonServer / mission.S256 / mission.ApprovedTools / mission.ExpiresAt
        """;

    public const string MissionPersonToken = """
        // Name the mission when requesting the person token; the PS checks it is
        // active and copies mission_s256 into the token. There is no mission header.
        var personToken = await exchange.RequestPersonTokenAsync(
            "https://ps.example", "https://resource.example",
            new TokenExchangeRequest { MissionS256 = mission.S256 });
        """;

    public const string MissionChallenge = """
        // Present the mission person token; the resource copies its mission_s256
        // into the resource_token.
        using var personClient = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy)
            .UseJwt(personToken)
            .Build();
        var resp = await personClient.GetAsync(resourceUrl); // → 401 requirement=auth-token
        var resourceToken = AAuthRequirementHeader.Parse(
            resp.Headers.GetValues(AAuthRequirementHeader.Name).First()).ResourceToken;
        """;

    public const string MissionExchange = """
        // The resource_token carries mission_s256; because (resource, trips.read)
        // is in the mission scope, the PS mints the auth_token SILENTLY.
        var authToken = await exchange.ExchangeAsync("https://ps.example", resourceToken, personToken);
        // Or, end-to-end: WithMission + WithChallengeHandling handle person token → 401 → exchange → retry.
        """;

    public const string MissionReplay = """
        using var client = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy)
            .UseJwt(authToken)
            .Build();
        var data = await client.GetAsync(resourceUrl); // 200 + mission round-tripped
        """;

    public const string MissionElevatedChallenge = """
        // Same mission person token, but the ELEVATED endpoint requires
        // trips.book — a scope the mission never declared.
        using var personClient = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy)
            .UseJwt(personToken)
            .Build();
        var resp = await personClient.GetAsync(elevatedUrl); // → 401 requirement=auth-token
        var resourceToken = AAuthRequirementHeader.Parse(
            resp.Headers.GetValues(AAuthRequirementHeader.Name).First()).ResourceToken;
        """;

    public const string MissionElevatedExchange = """
        // trips.book is OUTSIDE the mission's intent, so the PS
        // cannot mint silently — it returns 202 and asks the user to decide.
        // The configured policy may request consent or deny the scope.
        var authToken = await exchange.ExchangeAsync("https://ps.example", resourceToken,
            new TokenExchangeRequest { PresentedToken = personToken, OnInteractionRequired = SurfaceToUser });
        """;

    public const string MissionElevatedPoll = """
        // Once the user approves, the poll returns the elevated auth_token.
        // The consent accrues to the mission, so a later elevated request
        // can resolve silently under the same authorized context.
        var poller = new DeferredPoller(signedClient);
        using var pendingResponse = await poller.PollAsync(pendingUri);
        var elevatedAuthToken = (string)JsonNode.Parse(
            await pendingResponse.Content.ReadAsStringAsync())!["auth_token"]!;
        """;

    public const string MissionElevatedReplay = """
        using var client = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy)
            .UseJwt(elevatedAuthToken)
            .Build();
        var data = await client.GetAsync(elevatedUrl); // 200 + elevated claims
        """;

    public const string MissionPreApproved = """
        // Pre-approved tools never hit the network — the SDK short-circuits.
        // We kept the MissionTool reference from the proposal, so we ask via
        // tool.ToAction() rather than re-typing the action name.
        var result = await session.RequestPermissionAsync(addToCalendarTool.ToAction());
        // result.IsGranted == true   (no PS call: add_to_calendar ∈ mission.ApprovedTools)
        """;

    public const string MissionPermissionPrompt = """
        // cancel_booking is NOT pre-approved → the PS prompts the user.
        var result = await session.RequestPermissionAsync(
            new MissionAction("cancel_booking"),
            options: new GovernanceOptions { OnInteractionRequired = SurfaceToUser });
        // SDK POSTs /permission → 202; surfaces the link; polls for the decision.
        """;

    public const string MissionPollPermission = """
        // The poll returns a DECISION, not a token. The gate-2 auth_token is
        // unaffected by whatever the user chooses here.
        if (!result.IsGranted)
            throw new InvalidOperationException(result.Reason); // user denied
        // On grant: run cancel_booking, then report it to the audit_endpoint.
        await session.RecordAuditAsync(new MissionAction("cancel_booking"));
        """;

    public const string MissionInspect = """
        // One mission approval governed the whole session:
        //   gate 1  mission creation .... PROMPT
        //   gate 2  trips.read token ........ SILENT (in scope)
        //   gate 3  elevated scope ...... PROMPT (out of mission scope)
        //   gate 4  add_to_calendar tool ..... SILENT (pre-approved, local)
        //   gate 5  cancel_booking action . PROMPT (out of scope)
        // The PS is the policy-enforcement point; the resource stays oblivious.
        """;

    // ── Combined mission + call chain (§Clarification Chat, §Call Chaining) ──

    public const string MissionChainClarify = """
        // Requesting trips.book is OUT of the mission's intent, so the
        // PS opens a clarification chat BEFORE asking the user to decide.
        var authToken = await exchange.ExchangeAsync("https://ps.example", resourceToken,
            new TokenExchangeRequest
            {
                PresentedToken = personToken,
                // The SDK surfaces the PS's question and lets the agent answer.
                OnClarificationRequired = (q, _) =>
                    Task.FromResult(ClarificationResponse.Respond(
                        "Booking the trip needs permission to reserve and pay.")),
                OnInteractionRequired = SurfaceToUser,
            });
        // Raw HTTP: POST /token → 202 + AAuth-Requirement: requirement=clarification
        //           + { clarification: "Why does this mission need…?" }
        """;

    public const string MissionChainAnswer = """
        // Answer the PS's question on the mission-pending URL. The PS records the
        // exchange in the mission log and readies the user's decision.
        using var req = new HttpRequestMessage(HttpMethod.Post, missionPendingUrl);
        req.Content = JsonContent.Create(new
        {
            action = "clarification_response",
            clarification_response =
                "Booking the trip needs permission to reserve and pay.",
        });
        var resp = await signedClient.SendAsync(req); // → 204 No Content
        using var pending = await signedClient.GetAsync(missionPendingUrl); // -> 202
        var requirement = AAuthRequirementHeader.Parse(
            pending.Headers.GetValues(AAuthRequirementHeader.Name).Single());
        var interaction = Interaction.FromRequirement(requirement, SampleEgress.Policy)!;
        // Surface interaction.Url + "?code=" + interaction.Code, not the pending ID.
        """;

    public const string MissionChainForward = """
        // The SAME mission now governs a multi-agent CALL CHAIN. WithMission names
        // mission_s256 on the person token request; WithChallengeHandling threads the
        // silent in-scope exchange; the Concierge chains with our auth token as
        // upstream_token, so the PS governs the downstream hop by the same mission.
        using var client = AAuthClientBuilder.SelfIssuing(key).WithEgressPolicy(SampleEgress.Policy)
            .As(issuer, agentId).WithKid(keyId)
            .WithPersonServer("https://ps.example")
            .WithMission(mission)
            .WithChallengeHandling()      // (Concierge, concierge) is in scope
            .Build();
        var resp = await client.GetAsync("https://concierge.example/mission");
        // 200: { chain, upstream, concierge, downstream } — downstream is
        // Trips's /trips result carrying the same mission_s256. NO prompt: every hop in scope.
        """;

    public const string MissionChainLog = """
        // DEMO-ONLY: read the mission's auditable trail by its s256 (§Mission Log).
        var resp = await client.GetAsync($"https://ps.example/admin/mission-log/{s256}");
        var log = await resp.Content.ReadFromJsonAsync<JsonObject>();
        Console.WriteLine(log!.ToJsonString());
        // The 'clarification' entry records the question + the agent's answer.
        """;
}

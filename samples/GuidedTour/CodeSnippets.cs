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
            Issuer = "https://ap.example",
            Subject = "aauth:myapp@ap.example",
            KeyId = "sample-key-1",
            Key = key,
            PersonServer = "https://ps.example",
        }.Build();
        """;

    public const string DiscoverAp = """
        // AP metadata: GET /.well-known/aauth-agent.json
        var meta = await metadata.FetchAsync(
            "https://ap.example/.well-known/aauth-agent.json");
        var enrolEndpoint = (string)meta["enrol_endpoint"];
        """;

    public const string EnrolWithAp = """
        var apClient = new AgentProviderClient(httpClient, keyStore);
        var result = await apClient.EnrolAsync(
            apIssuer: "https://ap.example",
            agentId: "aauth:myapp@ap.example",
            enrollEndpoint: "https://ap.example/enrol",
            personServer: "https://ps.example");

        // result.Key             — Ed25519 signing key
        // result.AgentToken      — aa-agent+jwt from the AP
        // result.LocalKeyHandle  — agent-local IKeyStore handle (defaults to the durable key's JWK thumbprint)
        // result.AgentTokenKid   — AP-published kid (required for jwks_uri mode)
        // result.JwksUri         — per-agent JWKS endpoint
        """;

    public const string DiscoverResource = """
        // Resource metadata: GET /.well-known/aauth-resource.json
        var meta = await metadata.FetchAsync(
            "https://resource.example/.well-known/aauth-resource.json");
        """;

    public const string SignedGetHwk = """
        using var client = new AAuthClientBuilder(key)
            .UseHwk()
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=hwk;jkt="<thumbprint>";jwk="<public-key>"
        """;

    public const string SignedGetJwksUri = """
        // kid must match the AP's published JWKS entry.
        // The AP returns this as key_id at enrollment — there is no valid fallback.
        var kid = result.AgentTokenKid
            ?? throw new InvalidOperationException("AP did not return key_id for jwks_uri mode.");
        using var client = new AAuthClientBuilder(key)
            .UseJwksUri(result.JwksUri!, kid)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=jwks_uri;uri="<jwks_uri>";kid="<kid>"
        """;

    public const string SignedGetJwt = """
        using var client = AAuthClientBuilder.Enrolled(key)
            .RefreshingFrom(refreshEndpoint, localKeyHandle)
            .WithKeyStore(keyStore)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=jwt;jwt="<aa-agent+jwt>"
        """;

    public const string SignedGetJktJwt = """
        // jkt-jwt mode: the durable key signs a naming JWT that binds
        // the ephemeral signing key via cnf.jwk. The ephemeral key signs
        // the HTTP request. Supports key rotation without re-enrolment.
        //
        // Spec: "The AP verifies the durable-key signature on the naming JWT,
        //         looks up the enrollment by the durable key's thumbprint"
        var namingJwt = NamingJwtBuilder.Build(
            durableKey, ephemeralKey, apIssuer, durableKey.ComputeJwkThumbprint());

        using var client = new AAuthClientBuilder(ephemeralKey)
            .UseJktJwt(() => namingJwt)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=jkt-jwt;jwt="<naming-jwt>";jkt="<thumbprint>"
        """;

    public const string ParseChallenge = """
        // Parse the 401's AAuth-Requirement header
        var header = response.Headers
            .GetValues("AAuth-Requirement").First();
        var requirement = AAuthRequirementHeader.Parse(header);
        var resourceToken = requirement.ResourceToken;
        // resourceToken is an aa-resource+jwt with aud = PS URL
        """;

    public const string DiscoverPs = """
        // PS metadata: GET /.well-known/aauth-person.json
        var meta = await metadata.FetchAsync(
            "https://ps.example/.well-known/aauth-person.json");
        var tokenEndpoint = (string)meta["token_endpoint"];
        """;

    public const string TokenExchangeDirect = """
        // Automatic (recommended):
        using var client = AAuthClientBuilder.Enrolled(key)
            .RefreshingFrom(refreshEndpoint, localKeyHandle)
            .WithKeyStore(keyStore)
            .WithChallengeHandling(personServer: "https://ps.example")
            .Build();

        // Or manual:
        var exchange = new TokenExchangeClient(signedClient, metadata);
        var authToken = await exchange.ExchangeAsync(
            "https://ps.example", resourceToken);
        """;

    public const string TokenExchangeDeferred = """
        var exchange = new TokenExchangeClient(signedClient, metadata);
        var authToken = await exchange.ExchangeAsync(
            "https://ps.example",
            resourceToken,
            onInteractionRequired: async (interaction, ct) =>
            {
                Console.WriteLine($"Approve at: {interaction.BuildUserUrl()}");
            },
            pollerOptions: new DeferredPollerOptions
            {
                MaxTotalWait = TimeSpan.FromMinutes(5),
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

    public const string CallChainRetry = """
        // Retry Orchestrator with the auth_token.
        // From our side this looks like a normal retry — the chaining
        // happens server-side inside the Orchestrator:
        //   1. Orchestrator validates our auth_token
        //   2. Extracts it as upstream_token
        //   3. Calls downstream WhoAmI with its own agent token
        //   4. Exchanges at PS with upstream_token → nested act
        //   5. Retries WhoAmI with chained auth_token → 200
        using var chainClient = new AAuthClientBuilder(key)
            .UseJwt(authToken) // present the auth_token directly
            .Build();

        var response = await chainClient.GetAsync("https://orchestrator.example/");
        // 200 → combined result with full delegation chain
        """;

    public const string CallChainConvenience = """
        // Convenience: WithCallChaining routes downstream exchanges
        // automatically, passing upstream_token to the PS/AS.
        // Use this when building an intermediary service:
        using var downstream = AAuthClientBuilder.SelfIssuing(myKey)
            .As(myIssuer, myAgentId)
            .WithPersonServer(psUrl)
            .WithCallChaining(httpContext) // reads upstream token from request
            .Build();

        var result = await downstream.GetAsync("https://downstream.example/");
        // SDK handles: challenge → exchange with upstream_token → retry
        """;

    public const string FullAutomatic = """
        // --- Provisioning (separate tool / CLI — run once per install) ---
        var keyStore = FileKeyStore.Default();
        var enrolResult = await AAuthClientBuilder
            .Bootstrap("https://ap.example/enrol", "aauth:myapp@ap.example")
            .WithPersonServer("https://ps.example")
            .WithKeyStore(keyStore) // key generated inside store, never extracted
            .EnrolAsync();
        // Record enrolResult.LocalKeyHandle in app config — that's all you need

        // --- Application (every startup — load key by handle) ---
        var key = await keyStore.LoadAsync(localKeyHandle);
        using var client = AAuthClientBuilder.Enrolled(key)
            .RefreshingFrom(refreshEndpoint, localKeyHandle)
            .WithKeyStore(keyStore)
            .WithChallengeHandling("https://ps.example")
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // 401 → exchange → poll → retry all handled transparently
        """;

    // ── Mission-governed flow (§Missions, §PS Governance Endpoints) ──────────

    public const string MissionDiscoverPs = """
        // GET /.well-known/aauth-person.json
        var meta = await metadata.FetchAsync(
            "https://ps.example/.well-known/aauth-person.json");
        var mission     = (string)meta["mission_endpoint"];
        var tokenEp     = (string)meta["token_endpoint"];
        var permission  = (string)meta["permission_endpoint"];
        """;

    public const string MissionPropose = """
        var governance = new AAuthGovernanceClient(signedClient, metadata);
        var mission = await governance.Mission.ProposeAsync(
            "https://ps.example",
            new MissionProposal("Triage the user's inbox…")
            {
                Tools =
                {
                    new MissionTool("summarize"),
                    new MissionTool("send_email"),
                },
            },
            new GovernanceOptions { OnInteractionRequired = SurfaceToUser });
        // SDK POSTs /mission → 202; SurfaceToUser shows the consent link,
        // then the client polls until the user approves.
        """;

    public const string MissionPollCreate = """
        // The MissionClient polls the mission-pending URL internally and
        // returns the parsed, verified Mission once the user approves.
        // mission.Approver / mission.S256 / mission.ApprovedTools
        var verified = mission.VerifyS256(missionHeaderS256); // s256 integrity
        """;

    public const string MissionChallenge = """
        // Advertise the mission so the resource binds it into the resource_token.
        using var req = new HttpRequestMessage(HttpMethod.Get, resourceUrl);
        req.Headers.Add(
            AAuthMissionHeader.Name,
            AAuthMissionHeader.FormatStructured(mission.Approver, mission.S256));
        var resp = await signedClient.SendAsync(req); // → 401 + AAuth-Requirement
        var resourceToken = AAuthRequirementHeader.Parse(
            resp.Headers.GetValues(AAuthRequirementHeader.Name).First()).ResourceToken;
        """;

    public const string MissionExchange = """
        // The resource_token carries the mission claim; because (resource, whoami)
        // is in the mission scope, the PS mints the auth_token SILENTLY.
        var authToken = await exchange.ExchangeAsync("https://ps.example", resourceToken);
        // Or, end-to-end: AAuthClientBuilder handles 401 → exchange → retry for you.
        """;

    public const string MissionReplay = """
        using var client = new AAuthClientBuilder(key)
            .WithTokenRefresh(() => authToken)
            .Build();
        var data = await client.GetAsync(resourceUrl); // 200 + mission round-tripped
        """;

    public const string MissionElevatedChallenge = """
        // Same mission header, but the ELEVATED endpoint requires
        // whoami:elevated_scope — a scope the mission never declared.
        using var req = new HttpRequestMessage(HttpMethod.Get, elevatedUrl);
        req.Headers.Add(AAuthMissionHeader.Name,
            AAuthMissionHeader.FormatStructured(mission.Approver, mission.S256));
        var resp = await signedClient.SendAsync(req); // → 401 + AAuth-Requirement
        var resourceToken = AAuthRequirementHeader.Parse(
            resp.Headers.GetValues(AAuthRequirementHeader.Name).First()).ResourceToken;
        """;

    public const string MissionElevatedExchange = """
        // whoami:elevated_scope is OUTSIDE the mission's intent, so the PS
        // cannot mint silently — it returns 202 and asks the user to decide.
        // (Out-of-mission scopes prompt; they are never auto-denied.)
        var authToken = await exchange.ExchangeAsync("https://ps.example", resourceToken,
            new TokenExchangeRequest { OnInteractionRequired = SurfaceToUser });
        """;

    public const string MissionElevatedPoll = """
        // Once the user approves, the poll returns the elevated auth_token.
        // The consent accrues to the mission, so a later elevated request
        // would resolve silently.
        var data = await elevatedClient.GetAsync(elevatedUrl); // 200
        """;

    public const string MissionElevatedReplay = """
        using var client = new AAuthClientBuilder(key)
            .WithTokenRefresh(() => elevatedAuthToken)
            .Build();
        var data = await client.GetAsync(elevatedUrl); // 200 + elevated claims
        """;

    public const string MissionPreApproved = """
        // Pre-approved tools never hit the network — the SDK short-circuits.
        var result = await governance.Permission.RequestAsync(
            "https://ps.example", "send_email", mission);
        // result.IsGranted == true   (no PS call: send_email ∈ mission.ApprovedTools)
        """;

    public const string MissionPermissionPrompt = """
        // delete_inbox is NOT pre-approved → the PS prompts the user.
        var result = await governance.Permission.RequestAsync(
            "https://ps.example",
            new PermissionRequest("delete_inbox") { Mission = missionClaim },
            new GovernanceOptions { OnInteractionRequired = SurfaceToUser });
        // SDK POSTs /permission → 202; surfaces the link; polls for the decision.
        """;

    public const string MissionPollPermission = """
        // The poll returns a DECISION, not a token. The gate-2 auth_token is
        // unaffected by whatever the user chooses here.
        if (!result.IsGranted)
            throw new InvalidOperationException(result.Reason); // user denied
        // On grant: run delete_inbox, then report it to the audit_endpoint.
        await governance.Audit.RecordAsync("https://ps.example",
            new AuditRecord(missionClaim, "delete_inbox"));
        """;

    public const string MissionInspect = """
        // One mission approval governed the whole session:
        //   gate 1  mission creation .... PROMPT
        //   gate 2  whoami token ........ SILENT (in scope)
        //   gate 3  elevated scope ...... PROMPT (out of mission scope)
        //   gate 4  send_email tool ..... SILENT (pre-approved, local)
        //   gate 5  delete_inbox action . PROMPT (out of scope)
        // The PS is the policy-enforcement point; the resource stays oblivious.
        """;
}

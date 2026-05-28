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
}

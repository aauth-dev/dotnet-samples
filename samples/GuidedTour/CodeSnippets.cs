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

        // result.Key        — Ed25519 signing key
        // result.AgentToken — aa-agent+jwt from the AP
        // result.KeyId      — key ID at the AP
        // result.JwksUri    — per-agent JWKS endpoint
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
        using var client = new AAuthClientBuilder(key)
            .UseJwksUri(result.JwksUri, result.KeyId)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=jwks_uri;uri="<jwks_uri>";kid="<kid>"
        """;

    public const string SignedGetJwt = """
        using var client = new AAuthClientBuilder(key)
            .UseJwt(agentToken)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Signature-Key: sig=jwt;jwt="<aa-agent+jwt>"
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
        using var client = new AAuthClientBuilder(key)
            .UseJwt(agentToken)
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
            });

        var result = await poller.PollAsync(pendingUri);
        var authToken = (string)JsonNode.Parse(
            await result.Content.ReadAsStringAsync())!["auth_token"]!;
        """;

    public const string ReplayWithAuthToken = """
        // The ChallengeHandler does this automatically.
        // Manual approach:
        var holder = new AAuthTokenHolder(authToken);
        using var client = new AAuthClientBuilder(key)
            .UseJwt(() => holder.Current)
            .Build();

        var response = await client.GetAsync("https://resource.example/data");
        // Now signed with the auth_token → 200 OK
        """;

    public const string FullAutomatic = """
        // One-shot: bootstrap + challenge handling + deferred consent
        var (client, enrol) = await AAuthClientBuilder
            .Bootstrap("https://ap.example/enrol", "aauth:myapp@ap.example")
            .WithPersonServer("https://ps.example")
            .WithChallengeHandling()
            .EnrolAndBuildAsync();

        var response = await client.GetAsync("https://resource.example/data");
        // 401 → exchange → poll → retry all handled transparently
        """;
}

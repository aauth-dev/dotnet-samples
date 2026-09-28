namespace AAuth.Samples.Capabilities;

public static class WalletScenarioCode
{
    public static string For(WalletFlow flow) => flow switch
    {
        WalletFlow.DirectAs => DirectAs,
        WalletFlow.Revocation => Revocation,
        _ => Clarification,
    };

    public const string Clarification = """
        public static Task<string> ClarifyAsync(HttpClient signedAgent, MetadataClient metadata,
            string personServer, string resourceToken, string personToken,
            Func<Interaction, CancellationToken, Task> consent,
            Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> answer,
            CancellationToken cancellationToken)
            => new TokenExchangeClient(signedAgent, metadata).ExchangeAsync(personServer, resourceToken,
                new TokenExchangeRequest
                {
                    PresentedToken = personToken, OnInteractionRequired = consent, OnClarificationRequired = answer,
                },
                cancellationToken);

        public static ClarificationResponse Answer(string justification)
            => ClarificationResponse.Respond(justification);

        public static ClarificationResponse Cancel() => ClarificationResponse.Cancel();
        """;

    public const string DirectAs = """
        public static async Task<string> ReadWalletAsync(IAAuthKey key, string issuer, string agent,
            string kid, string upstreamToken, string wallet, AAuthEgressPolicy egress,
            CancellationToken cancellationToken)
        {
            using var client = AAuthClientBuilder.SelfIssuing(key).As(issuer, agent).WithKid(kid)
                .WithEgressPolicy(egress).WithCallChaining(upstreamToken)
                .WithChallengeHandling(options => options.Capabilities = Array.Empty<string>()).Build();
            using var response = await client.GetAsync(wallet + "/wallet", cancellationToken);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync(cancellationToken);
        }
        """;

    public const string Revocation = """
        public static async Task<RevocationResult> RevokePresentedPersonTokenAsync(HttpClient signedPersonServer,
            MetadataClient metadata, string accessServer, string personTokenId, DateTimeOffset personTokenExpiresAt,
            CancellationToken cancellationToken)
        {
            // The PS revokes, at the AS, the person token it presented; the AS cascades to the Wallet.
            var endpoint = (await metadata.FetchAccessServerMetadataAsync(accessServer, cancellationToken)).RevocationEndpoint
                ?? throw new InvalidOperationException("The Access Server publishes no revocation_endpoint.");
            return await new RevocationClient(signedPersonServer).RevokeAsync(new Uri(endpoint),
                personTokenId, personTokenExpiresAt, cancellationToken);
        }

        public static Task<string> RecoverAsync(HttpClient signedAgent, MetadataClient metadata,
            string personServer, string freshResourceToken, string personToken,
            Func<Interaction, CancellationToken, Task> consent, CancellationToken cancellationToken)
            => new TokenExchangeClient(signedAgent, metadata).ExchangeAsync(personServer, freshResourceToken,
                new TokenExchangeRequest { PresentedToken = personToken, OnInteractionRequired = consent }, cancellationToken);
        """;
}
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
            string personServer, string resourceToken,
            Func<Interaction, CancellationToken, Task> consent,
            Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> answer,
            CancellationToken cancellationToken)
            => new TokenExchangeClient(signedAgent, metadata).ExchangeAsync(personServer, resourceToken,
                new TokenExchangeRequest { OnInteractionRequired = consent, OnClarificationRequired = answer },
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
        public static Task<HttpStatusCode> RevokeAsync(HttpClient signedPersonServer,
            Uri resourceRevocationEndpoint, string issuer, string tokenId, CancellationToken cancellationToken)
            => new RevocationClient(signedPersonServer).RevokeAsync(resourceRevocationEndpoint,
                new TokenKey(issuer, tokenId), cancellationToken);

        public static Task<string> RecoverAsync(HttpClient signedAgent, MetadataClient metadata,
            string personServer, string freshResourceToken,
            Func<Interaction, CancellationToken, Task> consent, CancellationToken cancellationToken)
            => new TokenExchangeClient(signedAgent, metadata).ExchangeAsync(personServer, freshResourceToken,
                new TokenExchangeRequest { OnInteractionRequired = consent }, cancellationToken);
        """;
}
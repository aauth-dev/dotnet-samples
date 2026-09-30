namespace AAuth.Samples.Capabilities;

public static class WalletScenarioCode
{
    public static string For(WalletFlow flow) => flow switch
    {
        WalletFlow.AsGrantChaining => AsGrantChaining,
        WalletFlow.Revocation => Revocation,
        _ => Clarification,
    };

    public const string Clarification = """
        public static Task<string> ClarifyAsync(AAuthAgent agent,
            string personServer, string resourceToken, string personToken,
            Func<Interaction, CancellationToken, Task> consent,
            Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> answer,
            CancellationToken cancellationToken)
            // The agent's TokenExchange client is signed as the agent, never with a carrier token.
            => agent.TokenExchange.ExchangeAsync(personServer, resourceToken,
                new TokenExchangeRequest
                {
                    PresentedToken = personToken, OnInteractionRequired = consent, OnClarificationRequired = answer,
                },
                cancellationToken);

        public static ClarificationResponse Answer(string justification)
            => ClarificationResponse.Respond(justification);

        public static ClarificationResponse Cancel() => ClarificationResponse.Cancel();
        """;

    public const string AsGrantChaining = """
        public static async Task<string> ReadWalletAsync(IAAuthSigner key, string issuer, string agent,
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
        public static Task<RevocationCascadeResult> RevokePersonTokenAsync(IServiceProvider services,
            string personTokenId, CancellationToken cancellationToken)
        {
            // The PS revokes its person token at its resource and at every AS it presented it to;
            // each AS cascades to the auth tokens it issued against it.
            var revocation = services.GetRequiredKeyedService<IAAuthRevocationService>(AAuthPersonServerBuilder.DefaultName);
            return revocation.RevokeTokenAsync(personTokenId, cancellationToken);
        }

        public static Task<string> RecoverAsync(AAuthAgent agent,
            string personServer, string freshResourceToken, string personToken,
            Func<Interaction, CancellationToken, Task> consent, CancellationToken cancellationToken)
            => agent.TokenExchange.ExchangeAsync(personServer, freshResourceToken,
                new TokenExchangeRequest { PresentedToken = personToken, OnInteractionRequired = consent }, cancellationToken);
        """;
}
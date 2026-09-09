using AAuth.Discovery;

namespace AAuth.R3;

public sealed class R3DocumentReaderPolicy
{
    private readonly string _accessServer;
    private readonly HashSet<string> _personServers;

    public R3DocumentReaderPolicy(string designatedAccessServer, IEnumerable<string>? personServerEvaluators = null,
        AAuthEgressPolicy? egressPolicy = null)
    {
        var policy = egressPolicy ?? AAuthEgressPolicy.Production;
        policy.ValidateIdentifier(designatedAccessServer);
        _accessServer = designatedAccessServer;
        _personServers = new HashSet<string>(personServerEvaluators ?? [], StringComparer.Ordinal);
        foreach (var identifier in _personServers) policy.ValidateIdentifier(identifier);
    }

    public bool Allows(R3VerifiedFetcher fetcher) => fetcher.Scheme == AAuthConstants.Schemes.JwksUri &&
        (fetcher.Identifier == _accessServer && fetcher.ParsedKey.Dwk == AAuthConstants.DwkFiles.Access ||
         _personServers.Contains(fetcher.Identifier) && fetcher.ParsedKey.Dwk == AAuthConstants.DwkFiles.Person);
}
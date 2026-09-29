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

    /// <summary>
    /// Per-document entitlement for a Person Server evaluator: given the request and
    /// the PS identifier, whether this PS may read the requested document (for
    /// example, the PS named by the resource token that references it). When set, a
    /// configured evaluator that is not entitled gets <c>404</c>. The designated
    /// Access Server is not affected.
    /// </summary>
    public Func<Microsoft.AspNetCore.Http.HttpContext, string, bool>? IsEntitledPersonServer { get; init; }
}
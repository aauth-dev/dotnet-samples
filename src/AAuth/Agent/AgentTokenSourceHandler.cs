using System.Net.Http;

namespace AAuth.Agent;

internal sealed class AgentTokenSourceHandler(Func<string> source, AAuthTokenHolder holder, string? initialToken) : DelegatingHandler
{
    private string? _lastSource = initialToken;
    private readonly object _gate = new();

    // Only the token update is serialized: concurrent requests proceed in parallel and each is
    // signed with the latest agent token.
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // A cancelled request neither reads the token source nor reaches the network.
        if (cancellationToken.IsCancellationRequested) return Task.FromCanceled<HttpResponseMessage>(cancellationToken);
        lock (_gate)
        {
            var token = source();
            if (token != _lastSource)
            {
                holder.Update(token);
                _lastSource = token;
            }
        }
        return base.SendAsync(request, cancellationToken);
    }
}
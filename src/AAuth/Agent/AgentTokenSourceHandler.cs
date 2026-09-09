using System.Net.Http;

namespace AAuth.Agent;

internal sealed class AgentTokenSourceHandler(Func<string> source, AAuthTokenHolder holder, string? initialToken) : DelegatingHandler
{
    private string? _lastSource = initialToken;
    private readonly SemaphoreSlim _gate = new(1, 1);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var token = source();
            if (token != _lastSource)
            {
                holder.Update(token);
                _lastSource = token;
            }
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _gate.Dispose();
        base.Dispose(disposing);
    }
}
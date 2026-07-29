using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Events.Discovery;

/// <summary>Creates Events-owned clients with redirects disabled and URL checks.</summary>
public static class EventsHttpClientFactory
{
    /// <summary>Creates a no-redirect client using the supplied policy.</summary>
    public static HttpClient Create(
        IEventsUrlPolicy? policy = null,
        HttpMessageHandler? innerHandler = null)
    {
        policy ??= new DefaultEventsUrlPolicy();
        innerHandler ??= new HttpClientHandler { AllowAutoRedirect = false };
        return new HttpClient(new EventsUrlPolicyHandler(policy) { InnerHandler = innerHandler });
    }

    /// <summary>Alias for <see cref="Create"/>.</summary>
    public static HttpClient CreateClient(IEventsUrlPolicy? policy = null, HttpMessageHandler? innerHandler = null) =>
        Create(policy, innerHandler);

    private sealed class EventsUrlPolicyHandler : DelegatingHandler
    {
        private readonly IEventsUrlPolicy _policy;

        public EventsUrlPolicyHandler(IEventsUrlPolicy policy) => _policy = policy;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri is null)
                throw new HttpRequestException("Events request has no URI.");
            await _policy.EnsureAllowedAsync(request.RequestUri, cancellationToken).ConfigureAwait(false);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}

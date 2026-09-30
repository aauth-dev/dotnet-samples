using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// <see cref="DelegatingHandler"/> that automatically handles 202 responses
/// with <c>requirement=interaction</c> or <c>requirement=approval</c> by
/// polling the <c>Location</c> URL until a terminal response is received.
/// </summary>
/// <remarks>
/// Per spec: on 202 + interaction, the agent extracts the URL and code,
/// notifies the user, then polls Location. On 202 + approval, the agent
/// waits and polls. Retry-After is honoured; default poll interval is 5s.
/// On 429, linear backoff of +5s per occurrence.
/// </remarks>
public sealed class InteractionHandler : DelegatingHandler
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; init; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    public AAuth.Discovery.AAuthTransportContract? TransportContract { get; init; }
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
    internal Func<TimeSpan, CancellationToken, Task>? DelayAsync { get; init; }
    private const string ApprovalRequirement = "approval";
    private static readonly TimeSpan BackoffIncrement = TimeSpan.FromSeconds(5);

    private readonly IAAuthInteractionHandler? _interactionHandler;
    private readonly IAAuthDeferredObserver? _observer;
    private readonly TimeSpan _pollingTimeout;
    private readonly TimeSpan _defaultPollInterval;
    private readonly TimeSpan _minPollInterval;
    private readonly int? _preferWaitSeconds;

    public InteractionHandler(
        Func<Interaction, CancellationToken, Task>? onInteractionRequired = null,
        Func<CancellationToken, Task>? onApprovalPending = null,
        TimeSpan? pollingTimeout = null,
        TimeSpan? defaultPollInterval = null,
        TimeSpan? minPollInterval = null,
        int? preferWaitSeconds = null,
        Action<HttpResponseMessage>? onPoll = null)
        : this(DelegateInteractionHandler.From(onInteractionRequired), DelegateDeferredObserver.From(onApprovalPending, onPoll),
            pollingTimeout, defaultPollInterval, minPollInterval, preferWaitSeconds)
    {
    }

    /// <summary>
    /// Handle deferred resource responses with the given handler and observer; a request's
    /// <see cref="AAuthRequestOptions.InteractionHandler"/> and <see cref="AAuthRequestOptions.DeferredObserver"/>
    /// override them.
    /// </summary>
    public InteractionHandler(IAAuthInteractionHandler? interactionHandler, IAAuthDeferredObserver? observer,
        TimeSpan? pollingTimeout = null, TimeSpan? defaultPollInterval = null, TimeSpan? minPollInterval = null,
        int? preferWaitSeconds = null)
    {
        _interactionHandler = interactionHandler;
        _observer = observer;
        _pollingTimeout = pollingTimeout ?? TimeSpan.FromMinutes(5);
        _defaultPollInterval = defaultPollInterval ?? TimeSpan.FromSeconds(5);
        _minPollInterval = minPollInterval ?? TimeSpan.FromMilliseconds(100);
        _preferWaitSeconds = preferWaitSeconds;
    }

    private IAAuthInteractionHandler? InteractionFor(HttpRequestMessage request)
        => request.Options.TryGetValue(AAuthRequestOptions.InteractionHandler, out var handler) ? handler : _interactionHandler;

    private IAAuthDeferredObserver? ObserverFor(HttpRequestMessage request)
        => request.Options.TryGetValue(AAuthRequestOptions.DeferredObserver, out var observer) ? observer : _observer;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (TransportContract is null) throw new InvalidOperationException("Interaction handlers require an explicit inner transport contract.");
        // Capabilities follow the handlers that resolve for this request (#aauth-capabilities).
        if (InteractionFor(request) is not null)
            request.Options.Set(AAuth.HttpSig.AAuthSigningHandler.RequestCapabilitiesKey, [Interaction.RequirementType]);
        var response = await AAuth.Discovery.AAuthHttpTransport.SendBoundedAsync(EgressPolicy, request,
            token => base.SendAsync(request, token), cancellationToken).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.Accepted)
            return response;

        using var timeout = new CancellationTokenSource(_pollingTimeout, TimeProvider);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            return await HandleDeferredAsync(request, response, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested && timeout.IsCancellationRequested)
        {
            response.Dispose();
            throw new TimeoutException("Interaction polling exceeded its total wait budget.", exception);
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    private async Task<HttpResponseMessage> HandleDeferredAsync(HttpRequestMessage request,
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var transportContract = TransportContract
            ?? throw new InvalidOperationException("Interaction handlers require an explicit inner transport contract.");
        var started = TimeProvider.GetTimestamp();
        var interactionHandler = InteractionFor(request);
        var observer = ObserverFor(request);
        string? handledInteraction = null;
        var approvalNotified = false;
        async Task<bool> DispatchAsync(HttpResponseMessage current)
        {
            if (!current.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values)) return true;
            foreach (var raw in values)
            {
                AAuthRequirementHeader.ParsedRequirement parsed;
                try { parsed = AAuthRequirementHeader.Parse(raw); }
                catch (FormatException) { continue; }
                if (parsed.Requirement == Interaction.RequirementType)
                {
                    var interaction = Interaction.FromRequirement(parsed, EgressPolicy);
                    if (interaction is null) throw new HttpRequestException("Invalid interaction requirement.");
                    var userUrl = interaction.BuildUserUrl();
                    if (userUrl == handledInteraction) return true;
                    if (interactionHandler is null)
                        throw new AAuthInteractionDeniedException(
                            "Server requires user interaction but no interaction handler is configured.");
                    await AAuth.Discovery.AAuthHttpTransport.AdmitInteractionAsync(EgressPolicy, transportContract,
                        interaction.Url, cancellationToken).ConfigureAwait(false);
                    await interactionHandler.OnInteractionRequiredAsync(interaction with { Source = InteractionSource.Resource },
                        cancellationToken).WaitAsync(cancellationToken).ConfigureAwait(false);
                    handledInteraction = userUrl;
                    return true;
                }
                if (parsed.Requirement == ApprovalRequirement)
                {
                    if (!approvalNotified && observer is not null)
                        await observer.OnApprovalPendingAsync(cancellationToken).WaitAsync(cancellationToken).ConfigureAwait(false);
                    approvalNotified = true;
                    return true;
                }
            }
            return false;
        }

        var locationUri = response.Headers.Location;
        if (locationUri is null)
        {
            response.Dispose();
            throw new HttpRequestException("Deferred response is missing the Location header.");
        }

        if (!locationUri.IsAbsoluteUri && request.RequestUri is not null)
            locationUri = new Uri(request.RequestUri, locationUri);

        locationUri = EgressPolicy.ValidatePendingLocation(request.RequestUri!, locationUri);

        try
        {
            if (!await DispatchAsync(response).ConfigureAwait(false)) return response;
        }
        catch
        {
            response.Dispose();
            throw;
        }

        // Get initial Retry-After from the 202 response
        var initialDelay = GetRetryAfter(response.Headers.RetryAfter) ?? _defaultPollInterval;
        response.Dispose();

        // Poll loop
        var backoff = TimeSpan.Zero;
        var delay = initialDelay;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var remaining = _pollingTimeout - TimeProvider.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero)
            {
                throw new TimeoutException(
                    $"Interaction/approval polling exceeded {_pollingTimeout.TotalSeconds:0}s timeout.");
            }

            // Enforce minimum poll interval
            if (delay < _minPollInterval)
                delay = _minPollInterval;
            if (delay > remaining) delay = remaining;

            if (delay > TimeSpan.Zero)
            {
                if (DelayAsync is { } delayAsync)
                    await delayAsync(delay, cancellationToken).ConfigureAwait(false);
                else
                    await Task.Delay(delay, TimeProvider, cancellationToken).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (TimeProvider.GetElapsedTime(started) >= _pollingTimeout)
                throw new TimeoutException("Interaction polling exceeded its total wait budget.");

            using var pollRequest = new HttpRequestMessage(HttpMethod.Get, locationUri);
            if (AAuthRequestOptions.GetAccount(request) is { } account)
                pollRequest.Options.Set(AAuthRequestOptions.Account, account);
            if (_preferWaitSeconds is { } waitSec)
                pollRequest.Headers.TryAddWithoutValidation("Prefer", $"wait={waitSec}");

            var pollResponse = await AAuth.Discovery.AAuthHttpTransport.SendBoundedAsync(EgressPolicy, pollRequest,
                token => base.SendAsync(pollRequest, token), cancellationToken).ConfigureAwait(false);

            try { observer?.OnPoll(pollResponse); }
            catch { pollResponse.Dispose(); throw; }

            if (pollResponse.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable)
            {
                if (pollResponse.StatusCode == HttpStatusCode.TooManyRequests) backoff += BackoffIncrement;
                delay = (GetRetryAfter(pollResponse.Headers.RetryAfter) ?? _defaultPollInterval) + backoff;
                pollResponse.Dispose();
                continue;
            }

            if (pollResponse.StatusCode != HttpStatusCode.Accepted)
            {
                return pollResponse;
            }

            try
            {
                if (pollResponse.Headers.Location is { } nextLocation)
                    locationUri = EgressPolicy.ValidatePendingLocation(locationUri, nextLocation);
                if (!await DispatchAsync(pollResponse).ConfigureAwait(false)) return pollResponse;
            }
            catch
            {
                pollResponse.Dispose();
                throw;
            }
            delay = GetRetryAfter(pollResponse.Headers.RetryAfter) ?? _defaultPollInterval;
            delay += backoff;
            pollResponse.Dispose();
        }
    }

    private TimeSpan? GetRetryAfter(RetryConditionHeaderValue? retryAfter)
    {
        if (retryAfter is null) return null;
        if (retryAfter.Delta is { } delta) return delta;
        if (retryAfter.Date is { } date)
        {
            var remaining = date - TimeProvider.GetUtcNow();
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }
        return null;
    }
}

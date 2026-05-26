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
    private const string ApprovalRequirement = "approval";
    private static readonly TimeSpan BackoffIncrement = TimeSpan.FromSeconds(5);

    private readonly Func<string, string, CancellationToken, Task>? _onInteractionRequired;
    private readonly Func<CancellationToken, Task>? _onApprovalPending;
    private readonly TimeSpan _pollingTimeout;
    private readonly TimeSpan _defaultPollInterval;
    private readonly TimeSpan _minPollInterval;
    private readonly int? _preferWaitSeconds;
    private readonly Action<HttpResponseMessage>? _onPoll;

    public InteractionHandler(
        Func<string, string, CancellationToken, Task>? onInteractionRequired = null,
        Func<CancellationToken, Task>? onApprovalPending = null,
        TimeSpan? pollingTimeout = null,
        TimeSpan? defaultPollInterval = null,
        TimeSpan? minPollInterval = null,
        int? preferWaitSeconds = null,
        Action<HttpResponseMessage>? onPoll = null)
    {
        _onInteractionRequired = onInteractionRequired;
        _onApprovalPending = onApprovalPending;
        _pollingTimeout = pollingTimeout ?? TimeSpan.FromMinutes(5);
        _defaultPollInterval = defaultPollInterval ?? TimeSpan.FromSeconds(5);
        _minPollInterval = minPollInterval ?? TimeSpan.FromMilliseconds(100);
        _preferWaitSeconds = preferWaitSeconds;
        _onPoll = onPoll;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.Accepted)
            return response;

        // Check for requirement header
        if (!response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values))
            return response;

        string? requirementType = null;
        AAuthInteraction? interaction = null;

        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            try
            {
                var parsed = AAuthRequirementHeader.Parse(raw);
                if (parsed.Requirement == AAuthInteraction.RequirementType)
                {
                    interaction = AAuthInteraction.FromRequirement(parsed);
                    requirementType = AAuthInteraction.RequirementType;
                    break;
                }
                if (parsed.Requirement == ApprovalRequirement)
                {
                    requirementType = ApprovalRequirement;
                    break;
                }
            }
            catch (FormatException)
            {
                // Skip malformed values
            }
        }

        if (requirementType is null)
            return response;

        // Must have a Location header for polling
        var locationUri = response.Headers.Location;
        if (locationUri is null)
            return response;

        if (!locationUri.IsAbsoluteUri && request.RequestUri is not null)
            locationUri = new Uri(request.RequestUri, locationUri);

        // Invoke the appropriate callback
        if (requirementType == AAuthInteraction.RequirementType && interaction is not null)
        {
            if (_onInteractionRequired is not null)
            {
                var userUrl = interaction.BuildUserUrl();
                await _onInteractionRequired(userUrl, interaction.Code, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                throw new AAuthInteractionDeniedException(
                    "Server requires user interaction but no OnInteractionRequired callback is configured.");
            }
        }
        else if (requirementType == ApprovalRequirement)
        {
            if (_onApprovalPending is not null)
            {
                await _onApprovalPending(cancellationToken).ConfigureAwait(false);
            }
        }

        // Get initial Retry-After from the 202 response
        var initialDelay = GetRetryAfter(response.Headers.RetryAfter) ?? _defaultPollInterval;
        response.Dispose();

        // Poll loop
        var deadline = DateTimeOffset.UtcNow + _pollingTimeout;
        var backoff = TimeSpan.Zero;
        var delay = initialDelay;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (DateTimeOffset.UtcNow + delay > deadline)
            {
                throw new TimeoutException(
                    $"Interaction/approval polling exceeded {_pollingTimeout.TotalSeconds:0}s timeout.");
            }

            // Enforce minimum poll interval
            if (delay < _minPollInterval)
                delay = _minPollInterval;

            if (delay > TimeSpan.Zero)
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);

            using var pollRequest = new HttpRequestMessage(HttpMethod.Get, locationUri);
            if (_preferWaitSeconds is { } waitSec)
                pollRequest.Headers.TryAddWithoutValidation("Prefer", $"wait={waitSec}");

            var pollResponse = await base.SendAsync(pollRequest, cancellationToken).ConfigureAwait(false);

            _onPoll?.Invoke(pollResponse);

            if (pollResponse.StatusCode == (HttpStatusCode)429)
            {
                // Linear backoff: +5s per 429
                backoff += BackoffIncrement;
                delay = (GetRetryAfter(pollResponse.Headers.RetryAfter) ?? _defaultPollInterval) + backoff;
                pollResponse.Dispose();
                continue;
            }

            if (pollResponse.StatusCode != HttpStatusCode.Accepted)
            {
                return pollResponse;
            }

            // Still 202, keep polling
            delay = GetRetryAfter(pollResponse.Headers.RetryAfter) ?? _defaultPollInterval;
            delay += backoff;
            pollResponse.Dispose();
        }
    }

    private static TimeSpan? GetRetryAfter(RetryConditionHeaderValue? retryAfter)
    {
        if (retryAfter is null) return null;
        if (retryAfter.Delta is { } delta) return delta;
        if (retryAfter.Date is { } date)
        {
            var remaining = date - DateTimeOffset.UtcNow;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }
        return null;
    }
}

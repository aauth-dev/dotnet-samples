using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// Relays a user interaction the agent cannot satisfy itself: a Person Server's or a resource's
/// <c>requirement=interaction</c> (#user-interaction). <see cref="Interaction.Source"/> says which.
/// </summary>
public interface IAAuthInteractionHandler
{
    /// <summary>Show <paramref name="interaction"/> to the user (<see cref="Interaction.BuildUserUrl"/>).</summary>
    Task OnInteractionRequiredAsync(Interaction interaction, CancellationToken cancellationToken);
}

/// <summary>Answers a Person Server's clarification question (#clarification-chat).</summary>
public interface IAAuthClarificationHandler
{
    /// <summary>Respond, update the request, or cancel it.</summary>
    Task<ClarificationResponse> OnClarificationRequiredAsync(ClarificationRequirement clarification,
        CancellationToken cancellationToken);
}

/// <summary>Observes a deferred resource response: approval pending, and each poll.</summary>
public interface IAAuthDeferredObserver
{
    /// <summary>A resource answered <c>202</c> with <c>requirement=approval</c>; called once per request.</summary>
    Task OnApprovalPendingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>A poll of the pending URL returned <paramref name="response"/>.</summary>
    void OnPoll(HttpResponseMessage response) { }
}

// Delegate properties on options and builders adapt to the same interfaces.
internal sealed class DelegateInteractionHandler(Func<Interaction, CancellationToken, Task> callback) : IAAuthInteractionHandler
{
    public Task OnInteractionRequiredAsync(Interaction interaction, CancellationToken cancellationToken)
        => callback(interaction, cancellationToken);

    public static IAAuthInteractionHandler? From(Func<Interaction, CancellationToken, Task>? callback)
        => callback is null ? null : new DelegateInteractionHandler(callback);
}

internal sealed class DelegateClarificationHandler(
    Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> callback) : IAAuthClarificationHandler
{
    public Task<ClarificationResponse> OnClarificationRequiredAsync(ClarificationRequirement clarification,
        CancellationToken cancellationToken) => callback(clarification, cancellationToken);

    public static IAAuthClarificationHandler? From(
        Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>>? callback)
        => callback is null ? null : new DelegateClarificationHandler(callback);
}

internal sealed class DelegateDeferredObserver(Func<CancellationToken, Task>? approvalPending,
    Action<HttpResponseMessage>? poll) : IAAuthDeferredObserver
{
    public Task OnApprovalPendingAsync(CancellationToken cancellationToken)
        => approvalPending?.Invoke(cancellationToken) ?? Task.CompletedTask;

    public void OnPoll(HttpResponseMessage response) => poll?.Invoke(response);

    public static IAAuthDeferredObserver? From(Func<CancellationToken, Task>? approvalPending, Action<HttpResponseMessage>? poll)
        => approvalPending is null && poll is null ? null : new DelegateDeferredObserver(approvalPending, poll);
}

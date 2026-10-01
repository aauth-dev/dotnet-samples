using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Headers;

namespace AAuth.Server.CallChaining;

/// <summary>One published downstream interaction of an <see cref="AAuthChainedOperation{TResult}"/>.</summary>
/// <param name="Version">Increases each time the downstream asks for a different interaction.</param>
/// <param name="Downstream">The downstream PS or AS interaction the user must complete.</param>
public sealed record AAuthChainedInteractionSnapshot(long Version, Interaction Downstream);

/// <summary>
/// Runs an intermediary's downstream work for §Interaction Chaining. When the downstream PS or AS
/// answers with <c>202</c> + <c>requirement=interaction</c>, the operation publishes the interaction
/// and lets the SDK keep polling the downstream pending URL with <c>GET</c> (§Polling with GET), so
/// the intermediary can return its own <c>202</c> at once and later "completes the original request
/// and returns the result at its pending URL". The downstream request is never re-sent.
/// </summary>
/// <remarks>
/// The operation runs in memory and outlives the inbound request, so it must not use that request's
/// <c>HttpContext</c>, features, services or <c>RequestAborted</c> after it starts. Pass the upstream
/// token with <see cref="AAuthRequestOptions.UpstreamToken"/> and attach <see cref="InteractionHandler"/>
/// with <see cref="AAuthRequestOptions.InteractionHandler"/> on every downstream request.
/// </remarks>
public sealed class AAuthChainedOperation<TResult>
{
    private static readonly TimeSpan MaxTimerDelay = TimeSpan.FromMilliseconds(uint.MaxValue - 1);
    private readonly object _gate = new();
    private readonly CancellationTokenSource _cancellation;
    private readonly TaskCompletionSource _parked = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private AAuthChainedInteractionSnapshot? _interaction;

    private AAuthChainedOperation(CancellationTokenSource cancellation)
    {
        _cancellation = cancellation;
        InteractionHandler = new PublishingHandler(this);
        Completion = Task.FromCanceled<TResult>(new CancellationToken(true));
    }

    /// <summary>The downstream work; completes with its result or faults with its failure.</summary>
    public Task<TResult> Completion { get; private set; }

    /// <summary>The latest downstream interaction, or <see langword="null"/> before the first one.</summary>
    public AAuthChainedInteractionSnapshot? Interaction
    {
        get { lock (_gate) return _interaction; }
    }

    /// <summary>
    /// The handler to attach to each downstream request. It records the interaction and returns
    /// normally, so the exchange keeps polling instead of aborting.
    /// </summary>
    public IAAuthInteractionHandler InteractionHandler { get; }

    /// <summary>
    /// Start <paramref name="operation"/> and wait until it either completes or first needs downstream
    /// user interaction. Check <see cref="Completion"/>: if it is not complete, park the operation and
    /// answer the caller with the intermediary's own <c>202</c>.
    /// </summary>
    /// <param name="operation">The downstream work, given the interaction handler and its cancellation token.</param>
    /// <param name="expiresAt">When to stop polling downstream, for example the upstream token's expiry.</param>
    /// <param name="cancellationToken">Stops the operation early, for example on host shutdown.</param>
    public static async Task<AAuthChainedOperation<TResult>> StartAsync(
        Func<IAAuthInteractionHandler, CancellationToken, Task<TResult>> operation,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        AAuthChainedOperation<TResult> chained;
        try
        {
            var lifetime = expiresAt - DateTimeOffset.UtcNow;
            if (lifetime <= TimeSpan.Zero) cancellation.Cancel();
            // Timers cannot run past ~49.7 days; beyond that only Cancel or the caller's token stop it.
            else if (lifetime < MaxTimerDelay) cancellation.CancelAfter(lifetime);
            chained = new AAuthChainedOperation<TResult>(cancellation);
        }
        catch
        {
            cancellation.Dispose();
            throw;
        }

        chained.Completion = chained.RunAsync(operation);
        // A caller may abandon a parked operation; observe a failure nobody awaits.
        _ = chained.Completion.ContinueWith(static task => _ = task.Exception, CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        await Task.WhenAny(chained.Completion, chained._parked.Task).ConfigureAwait(false);
        return chained;
    }

    /// <summary>Stop polling downstream, for example when the caller <c>DELETE</c>s its pending URL.</summary>
    public void Cancel()
    {
        try { _cancellation.Cancel(); }
        catch (ObjectDisposedException) { }
    }

    private async Task<TResult> RunAsync(Func<IAAuthInteractionHandler, CancellationToken, Task<TResult>> operation)
    {
        try
        {
            return await operation(InteractionHandler, _cancellation.Token).ConfigureAwait(false);
        }
        finally
        {
            _cancellation.Dispose();
        }
    }

    private void Publish(Interaction interaction)
    {
        lock (_gate)
        {
            if (_interaction is { } current && current.Downstream.BuildUserUrl() == interaction.BuildUserUrl()) return;
            _interaction = new AAuthChainedInteractionSnapshot((_interaction?.Version ?? 0) + 1, interaction);
        }
        _parked.TrySetResult();
    }

    private sealed class PublishingHandler(AAuthChainedOperation<TResult> owner) : IAAuthInteractionHandler
    {
        public Task OnInteractionRequiredAsync(Interaction interaction, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(interaction);
            owner.Publish(interaction);
            return Task.CompletedTask;
        }
    }
}

using AAuth.Errors;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

internal static class AAuthSourceGuard
{
    private static readonly TimeSpan RaceRecheckInterval = TimeSpan.FromMilliseconds(25);

    public static async Task<AAuthSourceGuardFailure?> CheckAsync(
        IJtiStore inventory,
        IReadOnlyCollection<TokenRegistration> sources,
        TimeProvider timeProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        ArgumentNullException.ThrowIfNull(sources);
        var now = timeProvider.GetUtcNow();
        foreach (var source in sources)
        {
            if (await inventory.IsRevokedAsync(source.Token, cancellationToken).ConfigureAwait(false))
                return AAuthSourceGuardFailure.Revoked(source);
            if (!await inventory.ContainsTokenAsync(source.Token, cancellationToken).ConfigureAwait(false))
                return AAuthSourceGuardFailure.Missing(source);
        }
        foreach (var source in sources)
        {
            if (source.Credential == TokenCredential.Resource)
                continue;
            if (source.ExpiresAt.ToUnixTimeSeconds() <= now.ToUnixTimeSeconds())
                return AAuthSourceGuardFailure.Expired(source);
        }
        return null;
    }

    public static async Task<(T? Value, AAuthSourceGuardFailure? Failure)> CheckThenActAsync<T>(
        IJtiStore inventory,
        IReadOnlyCollection<TokenRegistration> sources,
        TimeProvider timeProvider,
        Func<CancellationToken, ValueTask<T>> action,
        CancellationToken cancellationToken = default)
    {
        if (await CheckAsync(inventory, sources, timeProvider, cancellationToken).ConfigureAwait(false) is { } failure)
            return (default, failure);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        AAuthSourceGuardFailure? observedFailure = null;
        var actionTask = action(linked.Token).AsTask();
        var monitorTask = MonitorAsync();
        try
        {
            var completed = await Task.WhenAny(actionTask, monitorTask).ConfigureAwait(false);
            if (completed == monitorTask)
            {
                await monitorTask.ConfigureAwait(false);
                if (observedFailure is { } racedFailure)
                {
                    linked.Cancel();
                    _ = ObserveAsync(actionTask);
                    return (default, racedFailure);
                }
            }

            var value = await actionTask.ConfigureAwait(false);
            if (await CheckAsync(inventory, sources, timeProvider, cancellationToken).ConfigureAwait(false) is { } postFailure)
                return (default, postFailure);
            return (value, null);
        }
        catch (OperationCanceledException) when (observedFailure is { } racedFailure)
        {
            return (default, racedFailure);
        }
        finally
        {
            linked.Cancel();
            _ = ObserveAsync(monitorTask);
        }

        async Task MonitorAsync()
        {
            while (true)
            {
                await Task.Delay(RaceRecheckInterval, linked.Token).ConfigureAwait(false);
                if (await CheckAsync(inventory, sources, timeProvider, linked.Token).ConfigureAwait(false) is not { } current)
                    continue;
                observedFailure = current;
                linked.Cancel();
                return;
            }
        }
    }

    private static async Task ObserveAsync(Task task)
    {
        try { await task.ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        catch { }
    }
}

internal readonly record struct AAuthSourceGuardFailure(bool IsRevoked, TokenRegistration Source, bool IsMissing = false)
{
    public static AAuthSourceGuardFailure Revoked(TokenRegistration source) => new(true, source);
    public static AAuthSourceGuardFailure Missing(TokenRegistration source) => new(true, source, IsMissing: true);
    public static AAuthSourceGuardFailure Expired(TokenRegistration source) => new(false, source);

    public IResult ToFreshResult(IReadOnlyCollection<TokenRegistration> sources, DateTimeOffset now, IResult? otherwise = null)
    {
        if (!IsRevoked)
            return AAuthProblemDetails.SourceExpired(sources, now, otherwise);
        return AAuthProblemDetails.SourceRevoked(new TokenVerificationException(
            SignatureErrorCode.RevokedJwt, Detail()) { Credential = Source.Credential });
    }

    public IResult ToPendingResult()
        => AAuthProblemDetails.Polling(IsRevoked ? PollingErrorCode.Revoked : PollingErrorCode.Expired, Detail());

    public string Detail()
    {
        var noun = Source.Credential switch
        {
            TokenCredential.Agent => "agent token",
            TokenCredential.Resource => "resource token",
            TokenCredential.Subagent => "sub-agent token",
            TokenCredential.Upstream => "upstream token",
            TokenCredential.Presented => "presented token",
            _ when Source.TokenType == AgentTokenBuilder.TokenType => "agent token",
            _ when Source.TokenType == PersonTokenBuilder.TokenType => "person token",
            _ when Source.TokenType == AuthTokenBuilder.TokenType => "auth token",
            _ => SyntheticDependency(Source.Token.TokenId),
        };
        if (IsMissing)
            return $"The {noun} is no longer present in the token inventory.";
        return $"The {noun} was {(IsRevoked ? "revoked" : "expired")}.";
    }

    private static string SyntheticDependency(string jti)
    {
        if (jti.StartsWith("agent-person-binding ", StringComparison.Ordinal))
            return "agent-person binding";
        if (jti.StartsWith("agent-subject ", StringComparison.Ordinal))
            return "agent identity dependency";
        if (jti.StartsWith("mission ", StringComparison.Ordinal))
            return "mission dependency";
        return "source token";
    }
}

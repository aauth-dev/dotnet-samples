using System;
using System.Security.Cryptography;
using System.Text;
using AAuth.Agent;

namespace AAuth.Server.Governance;

internal enum MissionStatusEvaluationKind
{
    Active,
    NotFound,
    Terminated,
}

internal sealed record MissionStatusEvaluation(
    MissionStatusEvaluationKind Kind,
    StoredMission? Mission = null,
    string? TerminationReason = null);

internal static class MissionStatusEvaluator
{
    public static async Task<MissionStatusEvaluation> EvaluateAsync(
        IMissionStore store,
        string personServer,
        string missionS256,
        string expectedAgent,
        TimeProvider timeProvider,
        CancellationToken cancellationToken = default,
        string? upstreamMissionS256 = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(personServer);
        ArgumentException.ThrowIfNullOrWhiteSpace(missionS256);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAgent);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var stored = await store.GetAsync(personServer, missionS256, cancellationToken).ConfigureAwait(false);
        var agentMatches = FixedEquals(stored?.Agent, expectedAgent);
        var upstreamMatches = upstreamMissionS256 is not null && FixedEquals(upstreamMissionS256, missionS256);
        var authorized = stored is not null
            && FixedEquals(stored.S256, missionS256)
            && FixedEquals(stored.PersonServer, personServer)
            && (agentMatches || upstreamMatches);
        if (!authorized)
        {
            return new(MissionStatusEvaluationKind.NotFound);
        }

        if (stored!.State == MissionState.Terminated)
        {
            return new(MissionStatusEvaluationKind.Terminated, stored, NormalizeReason(stored.TerminationReason));
        }

        if (stored.ExpiresAt is { } expiresAt && expiresAt <= timeProvider.GetUtcNow())
        {
            await store.TerminateAsync(personServer, missionS256,
                AAuthConstants.MissionTerminationReasons.Expired, cancellationToken).ConfigureAwait(false);
            var terminated = await store.GetAsync(personServer, missionS256, cancellationToken).ConfigureAwait(false);
            return new(MissionStatusEvaluationKind.Terminated, terminated ?? stored,
                NormalizeReason(terminated?.TerminationReason) ?? AAuthConstants.MissionTerminationReasons.Expired);
        }

        return new(MissionStatusEvaluationKind.Active, stored);
    }

    private static string? NormalizeReason(string? reason)
        => string.IsNullOrWhiteSpace(reason) ? null : reason;

    private static bool FixedEquals(string? left, string? right)
    {
        var leftHash = SHA256.HashData(Encoding.UTF8.GetBytes(left ?? string.Empty));
        var rightHash = SHA256.HashData(Encoding.UTF8.GetBytes(right ?? string.Empty));
        return CryptographicOperations.FixedTimeEquals(leftHash, rightHash)
            && string.Equals(left, right, StringComparison.Ordinal);
    }
}

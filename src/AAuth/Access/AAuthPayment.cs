using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Access;

/// <summary>Payment details from an AS <c>402 Payment Required</c> response.</summary>
public sealed class AAuthPaymentChallenge
{
    /// <summary>Raw <c>WWW-Authenticate</c> payment challenge values, if present.</summary>
    public IReadOnlyList<string> WwwAuthenticate { get; init; } = [];

    /// <summary>Optional payment-protocol body returned by the AS.</summary>
    public JsonObject? Body { get; init; }

    /// <summary>The payment scheme used to key billing-cache entries.</summary>
    public string Scheme { get; init; } = AAuthConstants.Governance.InteractionTypes.Payment;

    internal static async Task<AAuthPaymentChallenge> FromResponseAsync(
        System.Net.Http.HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var challenges = response.Headers.WwwAuthenticate
            .Select(header => header.ToString())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
        JsonObject? body = null;
        if (response.Content is not null)
        {
            var raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(raw))
            {
                try { body = JsonNode.Parse(raw) as JsonObject; }
                catch (System.Text.Json.JsonException) { body = null; }
            }
        }
        return new AAuthPaymentChallenge
        {
            WwwAuthenticate = challenges,
            Body = body,
            Scheme = ParseScheme(challenges.FirstOrDefault()) ?? AAuthConstants.Governance.InteractionTypes.Payment,
        };
    }

    private static string? ParseScheme(string? challenge)
    {
        if (string.IsNullOrWhiteSpace(challenge)) return null;
        var trimmed = challenge.TrimStart();
        var end = trimmed.IndexOfAny([' ', '\t', ',']);
        return end <= 0 ? trimmed : trimmed[..end];
    }
}

/// <summary>Inputs supplied to an application payment settler.</summary>
public sealed class AAuthPaymentSettlementContext
{
    /// <summary>The AS payment challenge.</summary>
    public required AAuthPaymentChallenge Challenge { get; init; }

    /// <summary>The AS origin that issued the challenge.</summary>
    public required string AccessServerOrigin { get; init; }

    /// <summary>The AS pending URL to poll after settlement.</summary>
    public required Uri PendingUrl { get; init; }
}

/// <summary>Application verdict after attempting payment settlement.</summary>
public sealed class AAuthPaymentSettlementResult
{
    private AAuthPaymentSettlementResult(bool settled) => Settled = settled;

    /// <summary>True when payment was settled and the PS may poll the AS pending URL.</summary>
    public bool Settled { get; }

    /// <summary>Payment was settled.</summary>
    public static AAuthPaymentSettlementResult Success { get; } = new(true);

    /// <summary>Payment was not settled.</summary>
    public static AAuthPaymentSettlementResult Declined { get; } = new(false);
}

/// <summary>
/// Application seam for out-of-scope payment settlement. The SDK passes only
/// the payment challenge, AS origin, and pending URL; JWTs are never exposed to
/// this seam.
/// </summary>
public interface IAAuthPaymentSettler
{
    /// <summary>Attempt to settle the AS payment challenge.</summary>
    Task<AAuthPaymentSettlementResult> SettleAsync(
        AAuthPaymentSettlementContext context,
        CancellationToken cancellationToken = default);
}

/// <summary>Cache of established PS billing relationships by AS issuer and payment scheme.</summary>
public interface IAAuthBillingRelationshipCache
{
    /// <summary>Return true when the billing relationship is already established.</summary>
    Task<bool> IsEstablishedAsync(string accessServerIssuer, string scheme, CancellationToken cancellationToken = default);

    /// <summary>Record an established billing relationship.</summary>
    Task MarkEstablishedAsync(string accessServerIssuer, string scheme, CancellationToken cancellationToken = default);
}

/// <summary>Process-local billing relationship cache for samples and tests.</summary>
public sealed class InMemoryAAuthBillingRelationshipCache : IAAuthBillingRelationshipCache
{
    private readonly ConcurrentDictionary<(string AccessServerIssuer, string Scheme), byte> _entries = new();

    /// <inheritdoc />
    public Task<bool> IsEstablishedAsync(string accessServerIssuer, string scheme, CancellationToken cancellationToken = default)
        => Task.FromResult(_entries.ContainsKey((accessServerIssuer, scheme)));

    /// <inheritdoc />
    public Task MarkEstablishedAsync(string accessServerIssuer, string scheme, CancellationToken cancellationToken = default)
    {
        _entries[(accessServerIssuer, scheme)] = 0;
        return Task.CompletedTask;
    }
}

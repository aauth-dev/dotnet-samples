using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Agent;

/// <summary>
/// <see cref="DelegatingHandler"/> that checks the current agent token's
/// <c>exp</c> claim before each request and refreshes it via
/// <see cref="ITokenRefresher"/> when expiry is within the configured threshold.
/// </summary>
internal sealed class TokenRefreshHandler : DelegatingHandler
{
    private readonly AAuthTokenHolder _holder;
    private readonly ITokenRefresher _refresher;
    private readonly string _keyId;
    private readonly TimeSpan _refreshThreshold;
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    public TokenRefreshHandler(
        AAuthTokenHolder holder,
        ITokenRefresher refresher,
        string keyId,
        TimeSpan? refreshThreshold = null)
    {
        _holder = holder;
        _refresher = refresher;
        _keyId = keyId;
        _refreshThreshold = refreshThreshold ?? TimeSpan.FromSeconds(60);
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await EnsureTokenFreshAsync(cancellationToken).ConfigureAwait(false);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task EnsureTokenFreshAsync(CancellationToken cancellationToken)
    {
        var token = _holder.Current;

        // Lazy acquisition: no token yet — must fetch one.
        if (string.IsNullOrEmpty(token))
        {
            await AcquireInitialTokenAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        var exp = ReadExpClaim(token);
        if (exp is null)
            return;

        var remaining = exp.Value - DateTimeOffset.UtcNow;
        if (remaining > _refreshThreshold)
            return;

        await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-check after acquiring — another thread may have refreshed.
            token = _holder.Current;
            exp = ReadExpClaim(token);
            if (exp is not null && (exp.Value - DateTimeOffset.UtcNow) <= _refreshThreshold)
            {
                var context = BuildContext(token);
                var newToken = await _refresher.RefreshAsync(context, cancellationToken).ConfigureAwait(false);
                _holder.Update(newToken);
            }
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task AcquireInitialTokenAsync(CancellationToken cancellationToken)
    {
        await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-check — another thread may have acquired already.
            if (!string.IsNullOrEmpty(_holder.Current))
                return;

            var context = new TokenRefreshContext
            {
                CurrentToken = string.Empty,
                Issuer = string.Empty,
                AgentId = string.Empty,
                KeyId = _keyId,
            };
            var newToken = await _refresher.RefreshAsync(context, cancellationToken).ConfigureAwait(false);
            _holder.Update(newToken);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private TokenRefreshContext BuildContext(string token)
    {
        var payload = ReadPayloadUnsafe(token);
        var iss = (string?)payload["iss"] ?? string.Empty;
        var sub = (string?)payload["sub"] ?? string.Empty;
        return new TokenRefreshContext
        {
            CurrentToken = token,
            Issuer = iss,
            AgentId = sub,
            KeyId = _keyId,
        };
    }

    internal static DateTimeOffset? ReadExpClaim(string token)
    {
        var payload = ReadPayloadUnsafe(token);
        if (payload["exp"] is JsonNode expNode && expNode.GetValueKind() == JsonValueKind.Number)
        {
            var epoch = expNode.GetValue<long>();
            return DateTimeOffset.FromUnixTimeSeconds(epoch);
        }
        return null;
    }

    internal static JsonObject ReadPayloadUnsafe(string token)
    {
        var firstDot = token.IndexOf('.');
        if (firstDot < 0) return new JsonObject();
        var secondDot = token.IndexOf('.', firstDot + 1);
        if (secondDot < 0) return new JsonObject();

        var payloadSegment = token.Substring(firstDot + 1, secondDot - firstDot - 1);
        var bytes = Base64UrlEncoder.DecodeBytes(payloadSegment);
        return JsonNode.Parse(bytes) as JsonObject ?? new JsonObject();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _semaphore.Dispose();
        base.Dispose(disposing);
    }
}

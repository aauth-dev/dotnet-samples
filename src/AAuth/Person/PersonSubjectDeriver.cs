using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace AAuth.Person;

/// <summary>Pairwise directed subject derived for a person/resource pair.</summary>
public sealed record DerivedPersonSubject(string Subject, string KeyId);

/// <summary>Derives pairwise directed person-token subjects.</summary>
public interface IPersonSubjectDeriver
{
    /// <summary>Derive a stable directed <c>sub</c> for the person at the resource.</summary>
    Task<DerivedPersonSubject> DeriveAsync(
        string personServer, AAuthPersonKey personKey, string resource, CancellationToken cancellationToken = default);
}

/// <summary>HMAC-SHA-256 pairwise subject deriver backed by a versioned key ring.</summary>
public sealed class HmacPersonSubjectDeriver : IPersonSubjectDeriver
{
    private const int OutputBytes = 24;
    private readonly IOptionsMonitor<AAuthPersonServerOptions> _options;
    private readonly string _name;
    private readonly byte[] _ephemeralSecret = RandomNumberGenerator.GetBytes(32);

    public HmacPersonSubjectDeriver(IOptionsMonitor<AAuthPersonServerOptions> options, string name)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _name = name;
    }

    /// <inheritdoc />
    public Task<DerivedPersonSubject> DeriveAsync(
        string personServer, AAuthPersonKey personKey, string resource, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var options = _options.Get(_name);
        var (keyId, secret) = ActiveSecret(options);
        var input = Encoding.UTF8.GetBytes(personServer + "\0" + personKey.Value + "\0" + resource);
        var hmac = HMACSHA256.HashData(secret, input);
        return Task.FromResult(new DerivedPersonSubject(Base64Url(hmac.AsSpan(0, OutputBytes)), keyId));
    }

    private (string KeyId, byte[] Secret) ActiveSecret(AAuthPersonServerOptions options)
    {
        if (options.PairwiseSubjectSecrets.Count > 0)
        {
            var keyId = options.ActivePairwiseSubjectKeyId;
            if (string.IsNullOrWhiteSpace(keyId))
            {
                foreach (var candidate in options.PairwiseSubjectSecrets.Keys)
                {
                    keyId = candidate;
                    break;
                }
            }
            if (keyId is null || !options.PairwiseSubjectSecrets.TryGetValue(keyId, out var configured)
                || string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException("AAuthPersonServerOptions.ActivePairwiseSubjectKeyId must name a configured pairwise subject secret.");
            return (keyId, DecodeSecret(configured));
        }
        return ("ephemeral", _ephemeralSecret);
    }

    private static byte[] DecodeSecret(string value)
    {
        try { return Base64UrlDecode(value); }
        catch (FormatException)
        {
            return Encoding.UTF8.GetBytes(value);
        }
    }

    private static string Base64Url(ReadOnlySpan<byte> bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }
}

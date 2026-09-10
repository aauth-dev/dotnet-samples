using System;

namespace AAuth.Server;

public sealed record TokenKey
{
    public TokenKey(string issuer, string tokenId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenId);
        Issuer = issuer;
        TokenId = tokenId;
    }

    public string Issuer { get; }
    public string TokenId { get; }
}
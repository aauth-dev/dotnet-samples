using AAuth.Crypto;
using AAuth.Tokens;

namespace AAuth.HttpSig;

public interface ISignatureTokenVerifier
{
    string Scheme { get; }
    string TokenType { get; }
    Task<TokenVerifier.VerifiedToken> VerifyAsync(
        string jwt, IAAuthKey issuerKey, TokenVerifier verifier, CancellationToken cancellationToken);
}
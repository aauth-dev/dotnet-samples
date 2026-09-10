using AAuth.Crypto;
using AAuth.Tokens;

namespace AAuth.Server.Verification;

public sealed record AAuthVerifiedAssertion(string CompactToken,
    TokenVerifier.VerifiedToken Token, IAAuthKey HttpSigningKey);
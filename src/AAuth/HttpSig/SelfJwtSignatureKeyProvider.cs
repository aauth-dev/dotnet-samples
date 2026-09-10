namespace AAuth.HttpSig;

public sealed class SelfJwtSignatureKeyProvider(Func<string> tokenFactory, string label = "sig") : ISignatureKeyProvider
{
    public string GetSignatureKeyHeader() => SignatureKeyHeader.FormatSelfJwt(tokenFactory(), label);
}
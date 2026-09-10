namespace AAuth.HttpSig;

public sealed class JwksSignatureKeyProvider(string url, string kid, string label = "sig") : ISignatureKeyProvider
{
    public string GetSignatureKeyHeader() => SignatureKeyHeader.FormatJwks(url, kid, label);
}
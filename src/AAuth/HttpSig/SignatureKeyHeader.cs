using AAuth.Crypto;
using AAuth.Errors;
using StructuredFieldValues;

namespace AAuth.HttpSig;

public static class SignatureKeyHeader
{
    public const string Name = "Signature-Key";

    public static string FormatJwt(string jwt, string label = "sig") => FormatAssertion("jwt", jwt, label);
    public static string FormatJktJwt(string jwt, string label = "sig") => FormatAssertion("jkt-jwt", jwt, label);
    public static string FormatSelfJwt(string jwt, string label = "sig") => FormatAssertion("self-jwt", jwt, label);

    public static string FormatHwk(IAAuthKey key, string label = "sig")
    {
        ArgumentNullException.ThrowIfNull(key);
        var jwk = key.ToPublicJwk();
        KeyFactory.FromPublicJwk(jwk);
        return Label(label) + "=hwk" + string.Concat(new[] { "kty", "crv", "x", "y", "alg" }
            .Where(jwk.ContainsKey).Select(name => ";" + name + "=" + StructuredFields.String(jwk[name]!.GetValue<string>())));
    }

    public static string FormatJwksUri(string id, string dwk, string kid, string label = "sig") =>
        Label(label) + "=jwks_uri;id=" + Required(id) + ";dwk=" + Required(dwk) + ";kid=" + Required(kid);

    public static string FormatJwks(string url, string kid, string label = "sig") =>
        Label(label) + "=jwks;url=" + Required(url) + ";kid=" + Required(kid);

    public static string? GetJwt(string headerValue, string label = "sig")
    {
        var (scheme, parameters) = Parse(headerValue, label);
        return scheme == "jwt" && parameters.TryGetValue("jwt", out var value) ? value as string : null;
    }

    public static (string Scheme, IReadOnlyDictionary<string, object> Parameters) Parse(string headerValue, string label = "sig")
    {
        var member = StructuredFields.Member(headerValue, label, SignatureErrorCode.InvalidKey);
        if (member.Value is not Token scheme)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidKey, "Signature-Key scheme must be a structured token.");
        return ((string)scheme, member.Parameters);
    }

    private static string FormatAssertion(string scheme, string jwt, string label)
    {
        if (jwt.Contains('"') || jwt.Contains('\\'))
            throw new ArgumentException("Compact JWT cannot contain quotes or backslashes.", nameof(jwt));
        return Label(label) + "=" + scheme + ";jwt=" + Required(jwt);
    }

    private static string Required(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        return StructuredFields.String(value);
    }

    internal static string Label(string label)
    {
        if (string.IsNullOrEmpty(label) || SfvParser.ParseDictionary(label + "=?1", out var members) is not null
            || members.Count != 1 || !members.ContainsKey(label))
            throw new ArgumentException("Invalid signature dictionary label.", nameof(label));
        return label;
    }
}

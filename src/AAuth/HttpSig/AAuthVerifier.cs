using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;
using AAuth.Errors;
using StructuredFieldValues;

namespace AAuth.HttpSig;

/// <summary>
/// Verifies selected RFC 9421 request signatures using typed structured fields,
/// scheme-resolved keys and the AAuth required component profile.
/// </summary>
public sealed class AAuthVerifier
{
    public IReadOnlyDictionary<string, StructuredFieldType> StructuredFieldTypes { get; init; } =
        new Dictionary<string, StructuredFieldType>(StringComparer.Ordinal)
        {
            ["signature-key"] = StructuredFieldType.Dictionary,
            ["signature-input"] = StructuredFieldType.Dictionary,
            ["signature"] = StructuredFieldType.Dictionary,
            ["content-digest"] = StructuredFieldType.Dictionary,
            ["repr-digest"] = StructuredFieldType.Dictionary,
        };
    /// <summary>
    /// Signature validity window for the RFC 9421 <c>created</c> parameter,
    /// applied in both directions. Matches the AAuth spec's default of 60
    /// seconds; resources may advertise a different value via the
    /// <c>signature_window</c> field of their <c>aauth-resource.json</c> metadata.
    /// </summary>
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Clock injection point for deterministic tests.</summary>
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;

    /// <summary>
    /// Verify an inbound AAuth-signed HTTP request.
    /// </summary>
    /// <param name="method">Case-sensitive HTTP method.</param>
    /// <param name="authority">Host[:port] of the request target, will be lowercased.</param>
    /// <param name="path">Path component of the request target (already percent-encoded as on the wire).</param>
    /// <param name="signatureKey">Verbatim <c>Signature-Key</c> header value.</param>
    /// <param name="signatureInput">Verbatim <c>Signature-Input</c> header value.</param>
    /// <param name="signatureHeader">Verbatim <c>Signature</c> header value.</param>
    /// <param name="publicKey">Public key for HTTP-signature verification (resolved from scheme).</param>
    /// <param name="authorization">Verbatim <c>Authorization</c> header value, or null if absent.</param>
    /// <param name="mission">Verbatim <c>AAuth-Mission</c> header value, or null if absent.</param>
    /// <exception cref="AAuthVerificationException">If any check fails.</exception>
    public string Verify(
        string method,
        string authority,
        string path,
        string signatureKey,
        string signatureInput,
        string signatureHeader,
        IAAuthKey publicKey,
        string? authorization = null,
        string? mission = null,
        string label = "sig",
        IReadOnlyDictionary<string, string>? fields = null,
        IReadOnlyCollection<string>? requiredComponents = null,
        string? keyId = null,
        IReadOnlyDictionary<string, string[]>? fieldValues = null,
        string? requestScheme = null,
        string? query = null,
        string? requestTarget = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        var input = ValidateInput(signatureInput, label, authorization, mission, requiredComponents);
        SignatureKeyHeader.Parse(signatureKey, label);
        if (input.Parameters.TryGetValue("keyid", out var keyIdValue)
            && (keyIdValue is not string suppliedId || suppliedId != (keyId ?? publicKey.ComputeJwkThumbprint())))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidKey, "Signature keyid conflicts with Signature-Key.");
        var signature = StructuredFields.Member(signatureHeader, label);
        if (signature.Value is not ReadOnlyMemory<byte> signatureBytes)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidSignature, "Signature must be a byte sequence.");
        var sb = new StringBuilder();
        foreach (var component in (IReadOnlyList<ParsedItem>)input.Value)
        {
            var name = (string)component.Value;
            if (name.StartsWith('@') && component.Parameters.Count > 0)
                throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Unsupported derived component parameters.");
            var normalizedAuthority = authority.ToLowerInvariant();
            if (requestScheme is not null && Uri.TryCreate(requestScheme + "://" + authority, UriKind.Absolute, out var target))
                normalizedAuthority = target.Authority.ToLowerInvariant();
            var value = name switch
            {
                "@method" => method,
                "@authority" => normalizedAuthority,
                "@path" => string.IsNullOrEmpty(path) ? "/" : path,
                "@scheme" => requestScheme?.ToLowerInvariant(),
                "@query" => query is null ? null : query.Length == 0 ? "?" : query,
                "@request-target" => requestTarget,
                "@target-uri" => requestScheme is null ? null : requestScheme.ToLowerInvariant() + "://" + normalizedAuthority + path + query,
                "signature-key" => signatureKey,
                "authorization" => authorization,
                "aauth-mission" => mission,
                _ when name.StartsWith('@') => null,
                _ => fields is not null && fields.TryGetValue(name, out var field) ? field : null,
            };
            if (value is null)
                throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, $"Covered component '{name}' is unavailable.");
            value = name.StartsWith('@') ? value : CanonicalField(component, value,
                fieldValues is not null && fieldValues.TryGetValue(name, out var values) ? values : null);
            if (value.Any(character => character is '\r' or '\n' || character > 0x7f))
                throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Invalid characters in signature base component.");
            sb.Append(StructuredFields.Item(component)).Append(": ").Append(value).Append('\n');
        }
        sb.Append("\"@signature-params\": ").Append(StructuredFields.Item(input));
        var signatureBase = Encoding.ASCII.GetBytes(sb.ToString());
        if (!publicKey.Verify(signatureBase, signatureBytes.ToArray()))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidSignature, "HTTP signature verification failed.");
        return publicKey.ComputeJwkThumbprint() + "|" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(signatureBase));
    }

    internal ParsedItem ValidateInput(string signatureInput, string label, string? authorization = null,
        string? mission = null, IReadOnlyCollection<string>? requiredComponents = null)
    {
        var input = StructuredFields.Member(signatureInput, label);
        if (input.Value is not IReadOnlyList<ParsedItem> components || components.Count == 0)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Signature-Input requires an inner list.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        foreach (var component in components)
        {
            if (component.Value is not string name || name != name.ToLowerInvariant() || name.Length == 0
                || !identifiers.Add(name + StructuredFields.Parameters(component.Parameters.OrderBy(parameter => parameter.Key, StringComparer.Ordinal)
                    .ToDictionary(parameter => parameter.Key, parameter => parameter.Value))))
                throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Invalid or duplicate covered component.");
            if (!component.Parameters.ContainsKey("key") && !component.Parameters.ContainsKey("tr")) names.Add(name);
        }
        var required = AAuthSigningHandler.CoveredComponents.Concat(requiredComponents ?? []).ToHashSet(StringComparer.Ordinal);
        if (authorization is not null) required.Add("authorization");
        if (mission is not null) required.Add("aauth-mission");
        if (!required.IsSubsetOf(names))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Required covered components are missing.");
        if (!input.Parameters.TryGetValue("created", out var createdValue) || createdValue is not long created)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidSignature, "Signature-Input requires integer created.");
        var now = Clock().ToUnixTimeSeconds();
        if (created < now - (long)MaxAge.TotalSeconds)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidSignature, "Signature is older than the validity window.");
        if (created > now + (long)MaxAge.TotalSeconds)
            throw new AAuthVerificationException(SignatureErrorCode.ClockSkew, "Signature created is ahead of the verifier clock by more than the validity window.");
        if (input.Parameters.TryGetValue("expires", out var expiresValue)
            && (expiresValue is not long expires || expires < now || expires < created))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidSignature, "Signature expires is invalid or in the past.");
        foreach (var name in new[] { "keyid", "nonce", "tag" })
            if (input.Parameters.TryGetValue(name, out var value) && value is not string)
                throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, $"Signature {name} must be a string.");
        return input;
    }

    private string CanonicalField(ParsedItem component, string value, string[]? fieldValues)
    {
        var parameters = component.Parameters;
        if (parameters.Keys.Any(name => name is not ("sf" or "key" or "bs")))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Unsupported covered-component parameter.");
        if (parameters.TryGetValue("sf", out var structured) && structured is not true
            || parameters.TryGetValue("bs", out var binary) && binary is not true)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Component flags must be Boolean true.");
        if (parameters.ContainsKey("bs") && (parameters.ContainsKey("sf") || parameters.ContainsKey("key")))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "bs cannot be combined with sf or key.");
        if (parameters.ContainsKey("bs"))
            return string.Join(", ", (fieldValues ?? [value]).Select(field => ":" + Convert.ToBase64String(Encoding.Latin1.GetBytes(NormalizeField(field))) + ":"));
        value = fieldValues is null ? NormalizeField(value) : string.Join(", ", fieldValues.Select(NormalizeField));
        var knownType = StructuredFieldTypes.TryGetValue((string)component.Value, out var fieldType);
        if (parameters.TryGetValue("key", out var selected))
        {
            if (!knownType || fieldType != StructuredFieldType.Dictionary || selected is not string member)
                throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Component key must be a string.");
            value = StructuredFields.Item(StructuredFields.Member(value, member));
        }
        else if (parameters.ContainsKey("sf"))
        {
            if (!knownType) throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Unknown structured field type.");
            if (fieldType == StructuredFieldType.Dictionary && SfvParser.ParseDictionary(value, out var dictionary) is null)
                value = string.Join(", ", dictionary.Select(member => member.Key
                    + (member.Value.Value is true ? StructuredFields.Parameters(member.Value.Parameters) : "=" + StructuredFields.Item(member.Value))));
            else if (fieldType == StructuredFieldType.List && SfvParser.ParseList(value, out var list) is null)
                value = string.Join(", ", list.Select(StructuredFields.Item));
            else if (fieldType == StructuredFieldType.Item && SfvParser.ParseItem(value, out var item) is null)
                value = StructuredFields.Item(item);
            else throw new AAuthVerificationException(SignatureErrorCode.InvalidInput, "Invalid structured covered field.");
        }
        return value;
    }

    internal static string NormalizeField(string value) =>
        System.Text.RegularExpressions.Regex.Replace(value.Trim(' ', '\t'), "\\r\\n[ \\t]+", " ");

}

/// <summary>Thrown when an inbound AAuth signature fails verification.</summary>
public sealed class AAuthVerificationException : Exception
{
    public AAuth.Errors.SignatureErrorCode Code { get; }

    public AAuthVerificationException(AAuth.Errors.SignatureErrorCode code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    /// <summary>Create an exception with a message.</summary>
    public AAuthVerificationException(string message) : this(AAuth.Errors.SignatureErrorCode.InvalidSignature, message) { }

    /// <summary>Create an exception with a message and inner exception.</summary>
    public AAuthVerificationException(string message, Exception inner) : this(AAuth.Errors.SignatureErrorCode.InvalidSignature, message, inner) { }
}

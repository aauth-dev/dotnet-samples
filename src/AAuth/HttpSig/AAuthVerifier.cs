using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.HttpSig;

/// <summary>
/// Hand-rolled RFC 9421 signature verifier for the fixed AAuth covered
/// components. Mirrors <see cref="AAuthSigningHandler"/>: it reconstructs
/// the exact signature base the signer would have produced, checks the
/// <c>created</c> freshness window, and verifies the Ed25519 signature.
/// </summary>
/// <remarks>
/// Informed by NSign's parser (component ordering, structured-field
/// framing, quoted-string handling) but has no runtime dependency on it.
/// AAuth covers only <c>@method</c>, <c>@authority</c>, <c>@path</c>,
/// <c>signature-key</c> — no <c>@query</c>, no Content-Digest binding, no
/// extension components. Verifying that fixed set is small enough that
/// pulling in NSign's full pipeline costs more than it saves.
/// </remarks>
public sealed class AAuthVerifier
{
    /// <summary>
    /// Default freshness window for the RFC 9421 <c>created</c> parameter.
    /// Matches the AAuth spec's default of 60 seconds; resources may
    /// advertise a different value via the <c>signature_window</c> field of
    /// their <c>aauth-resource.json</c> metadata.
    /// </summary>
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Tolerated <c>created</c> drift into the future. A small one-sided
    /// window accommodates real-world NTP skew without widening the legitimate
    /// replay window the way a symmetric <see cref="MaxAge"/> would.
    /// </summary>
    public TimeSpan MaxFutureSkew { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Clock injection point for deterministic tests.</summary>
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;

    /// <summary>
    /// Verify an inbound AAuth-signed HTTP request.
    /// </summary>
    /// <param name="method">HTTP method, will be uppercased.</param>
    /// <param name="authority">Host[:port] of the request target, will be lowercased.</param>
    /// <param name="path">Path component of the request target (already percent-encoded as on the wire).</param>
    /// <param name="signatureKey">Verbatim <c>Signature-Key</c> header value.</param>
    /// <param name="signatureInput">Verbatim <c>Signature-Input</c> header value.</param>
    /// <param name="signatureHeader">Verbatim <c>Signature</c> header value.</param>
    /// <param name="publicKey">Public key extracted from the <c>Signature-Key</c> token (cnf.jwk).</param>
    /// <exception cref="AAuthVerificationException">If any check fails.</exception>
    public void Verify(
        string method,
        string authority,
        string path,
        string signatureKey,
        string signatureInput,
        string signatureHeader,
        AAuthKey publicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentException.ThrowIfNullOrEmpty(authority);
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentException.ThrowIfNullOrEmpty(signatureKey);
        ArgumentException.ThrowIfNullOrEmpty(signatureInput);
        ArgumentException.ThrowIfNullOrEmpty(signatureHeader);
        ArgumentNullException.ThrowIfNull(publicKey);

        // Parse the labelled signature parameters from `Signature-Input`.
        // RFC 9421 allows multiple labelled signatures in a dictionary; AAuth
        // emits exactly one with the fixed label `sig`. Anything else is
        // rejected for now — multi-signer support is a future extension.
        var (paramsLine, components, created) = ParseSignatureInput(signatureInput);

        // Validate the covered-component list matches AAuth's fixed shape.
        if (!components.SequenceEqual(AAuthSigningHandler.CoveredComponents, StringComparer.Ordinal))
        {
            throw new AAuthVerificationException(
                "Signature-Input covered components do not match AAuth's required set " +
                $"({string.Join(' ', AAuthSigningHandler.CoveredComponents)}).");
        }

        // Freshness check on `created` (RFC 9421 §3.2.1). Asymmetric: allow
        // up to MaxAge in the past (the spec's `signature_window`) and only a
        // small MaxFutureSkew window for NTP drift. The previous symmetric
        // tolerance widened the legitimate replay window by 2x.
        var now = Clock().ToUnixTimeSeconds();
        var diff = now - created;
        if (diff > (long)MaxAge.TotalSeconds || diff < -(long)MaxFutureSkew.TotalSeconds)
        {
            throw new AAuthVerificationException(
                $"Signature created={created} is outside the freshness window " +
                $"(MaxAge={(long)MaxAge.TotalSeconds}s, MaxFutureSkew={(long)MaxFutureSkew.TotalSeconds}s, current={now}).");
        }

        // Pull the signature bytes out of the Signature header.
        var signatureBytes = ParseSignature(signatureHeader);

        // Reconstruct the signature base bit-for-bit the same way
        // AAuthSigningHandler.Sign produces it.
        var sb = new StringBuilder();
        AppendComponent(sb, "@method", method.ToUpperInvariant());
        AppendComponent(sb, "@authority", authority.ToLowerInvariant());
        AppendComponent(sb, "@path", path);
        AppendComponent(sb, "signature-key", signatureKey);
        sb.Append("\"@signature-params\": ").Append(paramsLine);

        if (!publicKey.Verify(Encoding.ASCII.GetBytes(sb.ToString()), signatureBytes))
        {
            throw new AAuthVerificationException("Ed25519 signature verification failed.");
        }
    }

    private static void AppendComponent(StringBuilder sb, string name, string value)
    {
        sb.Append('"').Append(name).Append("\": ").Append(value).Append('\n');
    }

    /// <summary>Parse <c>sig=("@method" ...);created=NNN</c>.</summary>
    private static (string ParamsLine, IReadOnlyList<string> Components, long Created) ParseSignatureInput(string input)
    {
        var trimmed = input.Trim();
        const string prefix = AAuthSigningHandler.SignatureLabel + "=";
        if (!trimmed.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new AAuthVerificationException(
                $"Signature-Input does not start with '{AAuthSigningHandler.SignatureLabel}='.");
        }

        var paramsLine = trimmed[prefix.Length..];

        if (paramsLine.Length == 0 || paramsLine[0] != '(')
        {
            throw new AAuthVerificationException("Signature-Input must begin with a component list '('.");
        }

        var closeIdx = paramsLine.IndexOf(')');
        if (closeIdx < 0)
        {
            throw new AAuthVerificationException("Signature-Input component list is unterminated.");
        }

        var inner = paramsLine[1..closeIdx];
        var components = new List<string>();
        int i = 0;
        while (i < inner.Length)
        {
            while (i < inner.Length && inner[i] == ' ') { i++; }
            if (i >= inner.Length) { break; }
            if (inner[i] != '"')
            {
                throw new AAuthVerificationException("Component identifiers must be quoted strings.");
            }
            i++;
            var start = i;
            while (i < inner.Length && inner[i] != '"') { i++; }
            if (i >= inner.Length)
            {
                throw new AAuthVerificationException("Unterminated component identifier.");
            }
            components.Add(inner[start..i]);
            i++;
        }

        // Parse `;created=NNN` (the only parameter AAuth uses today).
        long created = -1;
        var tail = paramsLine[(closeIdx + 1)..];
        foreach (var rawPart in tail.Split(';'))
        {
            var part = rawPart.Trim();
            if (part.Length == 0) { continue; }
            var eq = part.IndexOf('=');
            if (eq < 0)
            {
                throw new AAuthVerificationException($"Malformed parameter '{part}'.");
            }
            var name = part[..eq].Trim();
            var value = part[(eq + 1)..].Trim();
            if (name == "created")
            {
                if (!long.TryParse(value, out created))
                {
                    throw new AAuthVerificationException($"Malformed created value '{value}'.");
                }
            }
            // Other parameters (alg, keyid, nonce, expires...) are not
            // covered by AAuth's profile yet; ignore them silently.
        }

        if (created < 0)
        {
            throw new AAuthVerificationException("Signature-Input is missing the 'created' parameter.");
        }

        return (paramsLine, components, created);
    }

    /// <summary>Parse <c>sig=:base64:</c> and return the raw signature bytes.</summary>
    private static byte[] ParseSignature(string signatureHeader)
    {
        var trimmed = signatureHeader.Trim();
        const string prefix = AAuthSigningHandler.SignatureLabel + "=:";
        if (!trimmed.StartsWith(prefix, StringComparison.Ordinal) || !trimmed.EndsWith(':'))
        {
            throw new AAuthVerificationException(
                $"Signature header must be of the form '{AAuthSigningHandler.SignatureLabel}=:<base64>:'.");
        }

        var b64 = trimmed[prefix.Length..^1];
        try
        {
            return Convert.FromBase64String(b64);
        }
        catch (FormatException ex)
        {
            throw new AAuthVerificationException("Signature header contains malformed base64.", ex);
        }
    }
}

/// <summary>Thrown when an inbound AAuth signature fails verification.</summary>
public sealed class AAuthVerificationException : Exception
{
    /// <summary>Create an exception with a message.</summary>
    public AAuthVerificationException(string message) : base(message) { }

    /// <summary>Create an exception with a message and inner exception.</summary>
    public AAuthVerificationException(string message, Exception inner) : base(message, inner) { }
}

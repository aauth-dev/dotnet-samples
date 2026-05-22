using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.HttpSig;

/// <summary>
/// <see cref="DelegatingHandler"/> that signs every outbound request per
/// RFC 9421 using the fixed AAuth covered components
/// (<c>@method</c>, <c>@authority</c>, <c>@path</c>, <c>signature-key</c>)
/// and attaches the carrier token via the <c>Signature-Key</c> header.
/// </summary>
/// <remarks>
/// This is a minimal direct implementation; see the implementation plan
/// for why NSign is not used here.
/// </remarks>
public sealed class AAuthSigningHandler : DelegatingHandler
{
    /// <summary>RFC 9421 signature label. AAuth uses <c>sig</c>.</summary>
    public const string SignatureLabel = "sig";

    /// <summary>
    /// The AAuth-mandated covered component identifiers, in order.
    /// </summary>
    /// <remarks>
    /// Note that <c>@query</c> is intentionally <em>not</em> covered: query
    /// parameters are not part of the AAuth signature base and therefore can
    /// be modified by intermediaries without invalidating the signature. The
    /// AAuth spec deliberately scopes signing to method, authority, path, and
    /// the carrier token in <c>signature-key</c>.
    /// </remarks>
    public static readonly IReadOnlyList<string> CoveredComponents = Array.AsReadOnly(new[]
    {
        "@method", "@authority", "@path", "signature-key",
    });

    private readonly AAuthKey _key;
    private readonly Func<string> _tokenFactory;
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>
    /// Optional observability hook. When set, the canonical RFC 9421
    /// signature base string is passed to this callback every time a
    /// request is signed, immediately before signing. Used by the Guided
    /// Tour sample to surface the signed-over bytes; not part of the
    /// production signing path.
    /// </summary>
    public Action<HttpRequestMessage, string>? OnSignatureBase { get; init; }

    /// <summary>
    /// Optional capabilities to declare on outbound requests via the
    /// <c>AAuth-Capabilities</c> header (§14.1). When set, the header is
    /// emitted on every signed request.
    /// </summary>
    public IReadOnlyList<string>? Capabilities { get; init; }

    /// <summary>Create a signing handler.</summary>
    /// <param name="key">The agent's signing key.</param>
    /// <param name="tokenFactory">
    /// Returns the JWT to embed in the <c>Signature-Key</c> header for each
    /// request (typically an agent token; later an auth token after the
    /// three-party flow). Exceptions thrown by the factory propagate verbatim
    /// out of <see cref="SendAsync"/>; callers are responsible for handling
    /// token-acquisition failures.
    /// </param>
    /// <param name="clock">Optional clock for deterministic tests.</param>
    public AAuthSigningHandler(
        AAuthKey key,
        Func<string> tokenFactory,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(tokenFactory);
        if (!key.HasPrivateKey)
        {
            throw new ArgumentException("Signing key must include a private component.", nameof(key));
        }

        _key = key;
        _tokenFactory = tokenFactory;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Sign(request);
        return base.SendAsync(request, cancellationToken);
    }

    /// <summary>Apply AAuth signature headers to <paramref name="request"/>.</summary>
    public void Sign(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestUri is null)
        {
            throw new InvalidOperationException("Request must have a RequestUri.");
        }

        var jwt = _tokenFactory();
        var signatureKey = SignatureKeyHeader.FormatJwt(jwt);
        var created = _clock().ToUnixTimeSeconds();

        var method = request.Method.Method.ToUpperInvariant();
        // RFC 9421 §2.2.3 / RFC 3986 §3.2.2: @authority MUST be lowercase.
        // Uri.Authority preserves the original host casing, so normalize.
        var authority = request.RequestUri.Authority.ToLowerInvariant();
        // RFC 9421 §2.2.7: @path is the path component of the request target
        // *as transmitted on the wire* — i.e. percent-encoded. Uri.AbsolutePath
        // can return an unescaped form for some inputs; GetComponents with
        // UriFormat.UriEscaped guarantees the wire form. GetComponents omits
        // the leading '/', so re-add it.
        var path = "/" + request.RequestUri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);

        var paramsLine = BuildSignatureParams(created, request);

        // RFC 9421 §2.5 signature base construction.
        //
        // Note on `signature-key`: we append the raw header value as emitted
        // by FormatJwt (literal `sig=jwt;jwt="..."`). RFC 9421 allows a `;sf`
        // parameter that asks the verifier to re-serialize the structured
        // field deterministically before signing; we don't use it here
        // because the value is emitted by this same library so producer
        // and verifier see identical bytes. If any intermediary rewrites
        // the header (whitespace, quoting, item ordering), signature
        // verification will fail — revisit `;sf` if we ever need to
        // interoperate with such intermediaries.
        var sb = new StringBuilder();
        AppendComponent(sb, "@method", method);
        AppendComponent(sb, "@authority", authority);
        AppendComponent(sb, "@path", path);
        AppendComponent(sb, "signature-key", signatureKey);
        // §HTTP Signatures Profile: authorization MUST be covered when present
        if (request.Headers.Authorization is not null)
        {
            AppendComponent(sb, "authorization", request.Headers.Authorization.ToString());
        }
        sb.Append("\"@signature-params\": ").Append(paramsLine);

        var signatureBase = sb.ToString();
        OnSignatureBase?.Invoke(request, signatureBase);

        var signature = _key.Sign(Encoding.ASCII.GetBytes(signatureBase));

        request.Headers.Remove(SignatureKeyHeader.Name);
        request.Headers.Remove("Signature-Input");
        request.Headers.Remove("Signature");

        request.Headers.TryAddWithoutValidation(SignatureKeyHeader.Name, signatureKey);
        request.Headers.TryAddWithoutValidation("Signature-Input", $"{SignatureLabel}={paramsLine}");
        request.Headers.TryAddWithoutValidation("Signature", $"{SignatureLabel}=:{Convert.ToBase64String(signature)}:");

        // Emit capabilities header if configured
        if (Capabilities is { Count: > 0 })
        {
            request.Headers.Remove(AAuthCapabilitiesHeader.Name);
            request.Headers.TryAddWithoutValidation(
                AAuthCapabilitiesHeader.Name,
                AAuthCapabilitiesHeader.Format(Capabilities));
        }
    }

    private static void AppendComponent(StringBuilder sb, string name, string value)
    {
        sb.Append('"').Append(name).Append("\": ").Append(value).Append('\n');
    }

    private static string BuildSignatureParams(long created, HttpRequestMessage request)
    {
        var sb = new StringBuilder("(");
        for (int i = 0; i < CoveredComponents.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(' ');
            }
            sb.Append('"').Append(CoveredComponents[i]).Append('"');
        }
        // §HTTP Signatures Profile: authorization MUST be covered when present
        if (request.Headers.Authorization is not null)
        {
            sb.Append(" \"authorization\"");
        }
        sb.Append(");created=").Append(created);
        return sb.ToString();
    }
}

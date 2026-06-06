using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;

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

    /// <summary>
    /// Per-request option carrying additional HTTP message component
    /// identifiers (e.g. <c>content-type</c>, <c>content-digest</c>) that
    /// MUST be covered by the signature in addition to the base AAuth
    /// components (§Covered Components). Set via
    /// <c>request.Options.Set(AdditionalComponentsKey, ...)</c>; the signer
    /// reads it on each <see cref="Sign(HttpRequestMessage)"/>. The values
    /// are resolved from the request's header fields at signing time.
    /// </summary>
    public static readonly HttpRequestOptionsKey<IReadOnlyList<string>> AdditionalComponentsKey
        = new("AAuth.AdditionalSignatureComponents");

    private readonly IAAuthKey _key;
    private readonly ISignatureKeyProvider _signatureKeyProvider;
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
    /// <c>AAuth-Capabilities</c> header (§AAuth-Capabilities). When set, the header is
    /// emitted on every signed request.
    /// </summary>
    public IReadOnlyList<string>? Capabilities { get; init; }

    /// <summary>Create a signing handler with a strategy-based key provider.</summary>
    /// <param name="key">The agent's signing key (must have private component).</param>
    /// <param name="signatureKeyProvider">Strategy that produces the Signature-Key header value.</param>
    /// <param name="clock">Optional clock for deterministic tests.</param>
    public AAuthSigningHandler(
        IAAuthKey key,
        ISignatureKeyProvider signatureKeyProvider,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(signatureKeyProvider);
        if (!key.HasPrivateKey)
        {
            throw new ArgumentException("Signing key must include a private component.", nameof(key));
        }

        _key = key;
        _signatureKeyProvider = signatureKeyProvider;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Create a signing handler (convenience for the <c>jwt</c> scheme).</summary>
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
        : this(key, new JwtSignatureKeyProvider(tokenFactory), clock)
    {
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await EnsureRequiredContentDigestAsync(request, cancellationToken).ConfigureAwait(false);
        Sign(request);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    // When a resource requires `content-digest` as an additional covered
    // component (RFC 9530) and the request carries a body without an explicit
    // Content-Digest header, compute it here so the signer can cover it. Only
    // SHA-256 is emitted. Requests without a body, or that already carry the
    // header, are left untouched. This buffering only happens when a resource
    // has actually demanded `content-digest`, so the common no-digest path is
    // unaffected. Direct callers of the synchronous <see cref="Sign"/> must
    // pre-populate Content-Digest themselves.
    private static async Task EnsureRequiredContentDigestAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Content is null)
        {
            return;
        }
        if (!request.Options.TryGetValue(AdditionalComponentsKey, out var requested)
            || requested is not { Count: > 0 })
        {
            return;
        }

        var needsDigest = false;
        foreach (var raw in requested)
        {
            if (!string.IsNullOrWhiteSpace(raw)
                && string.Equals(raw.Trim(), "content-digest", StringComparison.OrdinalIgnoreCase))
            {
                needsDigest = true;
                break;
            }
        }
        if (!needsDigest || request.Content.Headers.Contains("Content-Digest"))
        {
            return;
        }

        var body = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var hash = SHA256.HashData(body);
        // RFC 9530 §3: Content-Digest is a Dictionary structured field whose
        // member value is a Byte Sequence (`:...:`). RFC 9421 then signs over
        // the serialized field value verbatim.
        var value = $"sha-256=:{Convert.ToBase64String(hash)}:";
        request.Content.Headers.TryAddWithoutValidation("Content-Digest", value);
    }

    /// <summary>Apply AAuth signature headers to <paramref name="request"/>.</summary>
    public void Sign(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestUri is null)
        {
            throw new InvalidOperationException("Request must have a RequestUri.");
        }

        var signatureKey = _signatureKeyProvider.GetSignatureKeyHeader();
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

        // Additional covered components required by the resource (from its
        // metadata or a prior invalid_input error). Resolve each to its
        // current header value so it can be both listed in @signature-params
        // and appended to the signature base. Unresolvable components are
        // skipped here and validated below.
        var additional = ResolveAdditionalComponents(request);

        var paramsLine = BuildSignatureParams(created, request, additional);

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
        // §Mission context: when the agent operates in a mission context it
        // includes the AAuth-Mission header and adds aauth-mission to the
        // signed components. Auto-cover it so callers need not opt in.
        if (TryGetMissionComponent(request, out var missionValue))
        {
            AppendComponent(sb, "aauth-mission", missionValue);
        }
        foreach (var (name, value) in additional)
        {
            AppendComponent(sb, name, value);
        }
        sb.Append("\"@signature-params\": ").Append(paramsLine);

        var signatureBase = sb.ToString();
        OnSignatureBase?.Invoke(request, signatureBase);

        var signature = _key.Sign(Encoding.ASCII.GetBytes(signatureBase));

        request.Headers.Remove(AAuthConstants.Headers.SignatureKey);
        request.Headers.Remove(AAuthConstants.Headers.SignatureInput);
        request.Headers.Remove(AAuthConstants.Headers.Signature);

        request.Headers.TryAddWithoutValidation(AAuthConstants.Headers.SignatureKey, signatureKey);
        request.Headers.TryAddWithoutValidation(AAuthConstants.Headers.SignatureInput, $"{SignatureLabel}={paramsLine}");
        request.Headers.TryAddWithoutValidation(AAuthConstants.Headers.Signature, $"{SignatureLabel}=:{Convert.ToBase64String(signature)}:");

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

    // Resolve the AAuth-Mission header to its on-the-wire field value so it can
    // be covered as the `aauth-mission` component (§Mission context). Returns
    // false when the header is absent or empty.
    private static bool TryGetMissionComponent(HttpRequestMessage request, out string value)
    {
        value = string.Empty;
        if (!request.Headers.TryGetValues(AAuthMissionHeader.Name, out var values))
        {
            return false;
        }
        value = string.Join(", ", values);
        return !string.IsNullOrWhiteSpace(value);
    }

    private static string BuildSignatureParams(
        long created, HttpRequestMessage request,
        IReadOnlyList<(string Name, string Value)> additional)
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
        // §Mission context: aauth-mission is covered when the header is present.
        if (TryGetMissionComponent(request, out _))
        {
            sb.Append(" \"aauth-mission\"");
        }
        foreach (var (name, _) in additional)
        {
            sb.Append(" \"").Append(name).Append('"');
        }
        sb.Append(");created=").Append(created);
        return sb.ToString();
    }

    // Resolve the resource-required additional components (carried in
    // request.Options) to (name, value) pairs in declared order. Each name
    // is a lowercase HTTP field identifier; its value is taken from the
    // request's content headers (e.g. content-type, content-digest) or
    // request headers. Names are de-duplicated and the base AAuth components
    // (already covered) are never re-added. A required component whose value
    // is not present on the request is rejected, because signing over an
    // absent field would not satisfy the resource.
    private static IReadOnlyList<(string Name, string Value)> ResolveAdditionalComponents(
        HttpRequestMessage request)
    {
        if (!request.Options.TryGetValue(AdditionalComponentsKey, out var requested)
            || requested is not { Count: > 0 })
        {
            return Array.Empty<(string, string)>();
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var baseComponent in CoveredComponents)
        {
            seen.Add(baseComponent);
        }
        seen.Add("authorization");
        // aauth-mission is auto-covered from the header; never add it twice.
        seen.Add("aauth-mission");

        var resolved = new List<(string, string)>();
        foreach (var raw in requested)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }
            var name = raw.Trim().ToLowerInvariant();
            if (!seen.Add(name))
            {
                continue;
            }
            if (!TryResolveFieldValue(request, name, out var value))
            {
                var origin = request.RequestUri is { } uri
                    ? uri.GetComponents(
                        UriComponents.Scheme | UriComponents.Host | UriComponents.Port,
                        UriFormat.UriEscaped)
                    : "(unknown origin)";
                throw new InvalidOperationException(
                    $"Resource at {origin} requires signature component '{name}', but the request "
                    + "has no such header to sign over. Components AAuth can compute automatically "
                    + "(e.g. 'content-digest' on a body-bearing request) are added before signing; "
                    + "any other required component must be set on the request by the caller.");
            }
            resolved.Add((name, value));
        }
        return resolved;
    }

    private static bool TryResolveFieldValue(
        HttpRequestMessage request, string name, out string value)
    {
        // Content headers (content-type, content-digest, content-length, ...)
        // live on request.Content; everything else on request.Headers. RFC
        // 9421 §2.1: multiple field values are combined with ", ".
        if (request.Content?.Headers.TryGetValues(name, out var contentValues) == true)
        {
            value = string.Join(", ", contentValues);
            return true;
        }
        if (request.Headers.TryGetValues(name, out var headerValues))
        {
            value = string.Join(", ", headerValues);
            return true;
        }
        value = string.Empty;
        return false;
    }

    /// <summary>
    /// Create an <see cref="HttpClient"/> that signs every outbound request.
    /// </summary>
    /// <param name="key">The agent's signing key (must have private component).</param>
    /// <param name="provider">Strategy that produces the Signature-Key header value.</param>
    /// <param name="innerHandler">Optional inner handler (defaults to <see cref="HttpClientHandler"/>).</param>
    public static HttpClient CreateClient(
        IAAuthKey key,
        ISignatureKeyProvider provider,
        HttpMessageHandler? innerHandler = null)
    {
        var handler = new AAuthSigningHandler(key, provider)
        {
            InnerHandler = innerHandler ?? new HttpClientHandler()
        };
        return new HttpClient(handler);
    }
}

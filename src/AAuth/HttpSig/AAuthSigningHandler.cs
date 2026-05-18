using System;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
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
/// This is a minimal direct implementation; see Phase 1 implementation
/// decisions in the plan document for why NSign is not used here yet.
/// </remarks>
public sealed class AAuthSigningHandler : DelegatingHandler
{
    /// <summary>RFC 9421 signature label. AAuth uses <c>sig</c>.</summary>
    public const string SignatureLabel = "sig";

    /// <summary>The AAuth-mandated covered component identifiers, in order.</summary>
    public static readonly IReadOnlyList<string> CoveredComponents = new[]
    {
        "@method", "@authority", "@path", "signature-key",
    };

    private readonly AAuthKey _key;
    private readonly Func<string> _tokenFactory;
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>Create a signing handler.</summary>
    /// <param name="key">The agent's signing key.</param>
    /// <param name="tokenFactory">
    /// Returns the JWT to embed in the <c>Signature-Key</c> header for each
    /// request (typically an agent token; later an auth token after the
    /// three-party flow).
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
        var authority = request.RequestUri.Authority;
        var path = request.RequestUri.AbsolutePath;

        var paramsLine = BuildSignatureParams(created);

        // RFC 9421 §2.5 signature base construction.
        var sb = new StringBuilder();
        AppendComponent(sb, "@method", method);
        AppendComponent(sb, "@authority", authority);
        AppendComponent(sb, "@path", path);
        AppendComponent(sb, "signature-key", signatureKey);
        sb.Append("\"@signature-params\": ").Append(paramsLine);

        var signature = _key.Sign(Encoding.ASCII.GetBytes(sb.ToString()));

        request.Headers.Remove(SignatureKeyHeader.Name);
        request.Headers.Remove("Signature-Input");
        request.Headers.Remove("Signature");

        request.Headers.TryAddWithoutValidation(SignatureKeyHeader.Name, signatureKey);
        request.Headers.TryAddWithoutValidation("Signature-Input", $"{SignatureLabel}={paramsLine}");
        request.Headers.TryAddWithoutValidation("Signature", $"{SignatureLabel}=:{Convert.ToBase64String(signature)}:");
    }

    private static void AppendComponent(StringBuilder sb, string name, string value)
    {
        sb.Append('"').Append(name).Append("\": ").Append(value).Append('\n');
    }

    private static string BuildSignatureParams(long created)
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
        sb.Append(");created=").Append(created);
        return sb.ToString();
    }
}

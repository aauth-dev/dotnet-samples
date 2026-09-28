using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Errors;

namespace AAuth.Server;

/// <summary>
/// Sends a §Token Revocation request <c>{ "jti", "exp" }</c> over a server-signed
/// <see cref="HttpClient"/>. The issuer is the signer: a caller revokes only its own tokens.
/// </summary>
public sealed class RevocationClient
{
    internal static readonly string[] CoveredContent = ["content-type", "content-digest"];
    private readonly HttpClient _signedHttp;

    public RevocationClient(HttpClient signedHttp)
    {
        ArgumentNullException.ThrowIfNull(signedHttp);
        _ = AAuthHttpTransport.GetPolicy(signedHttp);
        _signedHttp = signedHttp;
    }

    /// <summary>
    /// Revoke the caller's token <paramref name="jti"/>, whose own expiration is
    /// <paramref name="expiresAt"/>. Transport failures propagate; every HTTP answer is returned.
    /// </summary>
    public async Task<RevocationResult> RevokeAsync(Uri endpoint, string jti, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = JsonContent.Create(new JsonObject { ["jti"] = jti, ["exp"] = expiresAt.ToUnixTimeSeconds() }),
        };
        request.Options.Set(HttpSig.AAuthSigningHandler.AdditionalComponentsKey, CoveredContent);
        using var response = await AAuthHttpTransport.SendAsync(_signedHttp, request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return Parse(response.StatusCode, response.Content.Headers.ContentType?.MediaType, body);
    }

    internal static RevocationResult Parse(HttpStatusCode status, string? mediaType, string body)
    {
        if (status == HttpStatusCode.OK)
        {
            if (body.Length == 0) return new() { StatusCode = status };
            return TryParseDownstream(mediaType, body, out var downstream)
                ? new() { StatusCode = status, Downstream = downstream }
                : new() { StatusCode = status, Failure = RevocationDownstreamError.RevocationUnavailable };
        }
        var error = ReadError(body);
        return new()
        {
            StatusCode = status,
            Error = error,
            Failure = status == HttpStatusCode.Forbidden && error == RevocationError.ToWireCode(RevocationErrorCode.UnsupportedIss)
                ? RevocationDownstreamError.RevocationUnsupported
                : RevocationDownstreamError.RevocationUnavailable,
        };
    }

    private static bool TryParseDownstream(string? mediaType, string body, out IReadOnlyList<RevocationDownstreamResult> downstream)
    {
        downstream = [];
        if (!string.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase)) return false;
        JsonNode? root;
        try { root = JsonNode.Parse(body); }
        catch (JsonException) { return false; }
        if (root is not JsonObject document) return false;
        if (!document.TryGetPropertyValue("downstream", out var member)) return true;
        if (member is not JsonArray entries) return false;
        var results = new List<RevocationDownstreamResult>(entries.Count);
        foreach (var entry in entries)
        {
            if (entry is not JsonObject item
                || item["recipient"] is not JsonValue recipientValue || !recipientValue.TryGetValue<string>(out var recipient)
                || string.IsNullOrWhiteSpace(recipient))
                return false;
            RevocationDownstreamError? error = null;
            if (item.TryGetPropertyValue("error", out var errorNode))
            {
                if (errorNode is not JsonValue errorValue || !errorValue.TryGetValue<string>(out var code)
                    || !RevocationError.TryParseDownstream(code, out var parsed))
                    return false;
                error = parsed;
            }
            results.Add(new(recipient, error));
        }
        downstream = results;
        return true;
    }

    private static string? ReadError(string body)
    {
        try { return JsonNode.Parse(body) is JsonObject problem && problem["error"] is JsonValue value && value.TryGetValue<string>(out var code) ? code : null; }
        catch (JsonException) { return null; }
    }
}
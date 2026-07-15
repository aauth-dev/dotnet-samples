using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;

namespace AAuth.Events.Http;

/// <summary>Events HTTP signature profile.</summary>
public enum EventsHttpProfile
{
    Bodyless,
    RegistrationJson,
    EventJson,
    Registration = RegistrationJson,
    Event = EventJson,
}

/// <summary>Successful HTTP verification result.</summary>
public sealed record EventsHttpVerificationResult(
    EventsHttpProfile Profile,
    long Created,
    string SignatureKey,
    byte[] Body);

/// <summary>Exact RFC 9421 verifier for the single Events <c>sig</c> label.</summary>
public sealed class EventsHttpMessageVerifier
{
    /// <summary>Maximum accepted age of a signature.</summary>
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromSeconds(60);
    /// <summary>Allowed future skew for the created parameter.</summary>
    public TimeSpan FutureSkew { get; init; } = TimeSpan.FromSeconds(5);
    /// <summary>Clock used for freshness checks.</summary>
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;
    /// <summary>Maximum buffered body size.</summary>
    public int MaxBodyBytes { get; init; } = AAuthEventsConstants.DefaultMaxBodyBytes;

    /// <summary>Verifies a request using the already resolved HTTP public key.</summary>
    public EventsHttpVerificationResult Verify(
        HttpRequestMessage request,
        IAAuthKey httpSignatureKey,
        EventsHttpProfile profile,
        string? wirePath = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(httpSignatureKey);
        try
        {
            RejectForbidden(request);
            var expected = Components(profile);
            var input = SingleHeader(request, "Signature-Input");
            var parsed = ParseSignatureInput(input);
            if (!SequenceEqual(parsed.Components, expected))
                throw Error(
                    parsed.Components.Count < expected.Count
                        ? EventsVerificationErrorCode.MissingCoveredComponent
                        : EventsVerificationErrorCode.UnexpectedCoveredComponent,
                    "The covered component sequence does not exactly match the Events profile.");
            var now = Clock().ToUnixTimeSeconds();
            if (parsed.Created > now + (long)FutureSkew.TotalSeconds)
                throw Error(EventsVerificationErrorCode.InvalidSignature, "Signature created time is in the future.");
            if (parsed.Created < now - (long)MaxAge.TotalSeconds)
                throw Error(EventsVerificationErrorCode.ExpiredToken, "Signature created time is stale.");

            var signatureKeyHeader = SingleHeader(request, SignatureKeyHeader.Name);
            var signature = ParseSignature(SingleHeader(request, "Signature"));
            var baseString = BuildSignatureBase(
                request, parsed.Components, parsed.Created, signatureKeyHeader, wirePath);
            if (!httpSignatureKey.Verify(Encoding.ASCII.GetBytes(baseString), signature))
                throw Error(EventsVerificationErrorCode.InvalidSignature, "HTTP signature verification failed.");

            var body = Array.Empty<byte>();
            if (profile == EventsHttpProfile.Bodyless && request.Content is not null)
                throw Error(EventsVerificationErrorCode.UnexpectedCoveredComponent,
                    "Bodyless Events requests must not carry content.");
            if (profile != EventsHttpProfile.Bodyless)
            {
                RequireJson(request);
                body = profile == EventsHttpProfile.EventJson
                    ? EventsRequestBody.ReadAndVerifyAsync(request, MaxBodyBytes).GetAwaiter().GetResult().Bytes
                    : EventsRequestBody.ReadAsync(request, MaxBodyBytes).GetAwaiter().GetResult();
                if (profile == EventsHttpProfile.EventJson &&
                    !request.Content!.Headers.Contains("Content-Digest"))
                    throw Error(EventsVerificationErrorCode.MissingCoveredComponent,
                        "Event profile requires Content-Digest.");
            }

            return new EventsHttpVerificationResult(profile, parsed.Created, signatureKeyHeader, body);
        }
        catch (EventsVerificationException) { throw; }
        catch (FormatException ex)
        {
            throw new EventsVerificationException(
                EventsVerificationErrorCode.MalformedRequest, ex.Message, ex);
        }
    }

    /// <summary>Verifies the bodyless profile.</summary>
    public EventsHttpVerificationResult VerifyBodyless(
        HttpRequestMessage request, IAAuthKey key, string? wirePath = null) =>
        Verify(request, key, EventsHttpProfile.Bodyless, wirePath);

    /// <summary>Verifies the registration profile.</summary>
    public EventsHttpVerificationResult VerifyRegistration(
        HttpRequestMessage request, IAAuthKey key, string? wirePath = null) =>
        Verify(request, key, EventsHttpProfile.RegistrationJson, wirePath);

    /// <summary>Verifies the event profile.</summary>
    public EventsHttpVerificationResult VerifyEvent(
        HttpRequestMessage request, IAAuthKey key, string? wirePath = null) =>
        Verify(request, key, EventsHttpProfile.EventJson, wirePath);

    /// <summary>Asynchronously verifies a request with cancellation support.</summary>
    public async Task<EventsHttpVerificationResult> VerifyAsync(
        HttpRequestMessage request,
        IAAuthKey httpSignatureKey,
        EventsHttpProfile profile,
        string? wirePath = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(httpSignatureKey);
        try
        {
            RejectForbidden(request);
            var expected = Components(profile);
            var parsed = ParseSignatureInput(SingleHeader(request, "Signature-Input"));
            if (!SequenceEqual(parsed.Components, expected))
                throw Error(parsed.Components.Count < expected.Count
                    ? EventsVerificationErrorCode.MissingCoveredComponent
                    : EventsVerificationErrorCode.UnexpectedCoveredComponent,
                    "The covered component sequence does not exactly match the Events profile.");
            CheckFresh(parsed.Created);
            var keyHeader = SingleHeader(request, SignatureKeyHeader.Name);
            var signature = ParseSignature(SingleHeader(request, "Signature"));
            var baseString = BuildSignatureBase(request, parsed.Components, parsed.Created, keyHeader, wirePath);
            if (!httpSignatureKey.Verify(Encoding.ASCII.GetBytes(baseString), signature))
                throw Error(EventsVerificationErrorCode.InvalidSignature, "HTTP signature verification failed.");
            var body = Array.Empty<byte>();
            if (profile != EventsHttpProfile.Bodyless)
            {
                RequireJson(request);
                body = profile == EventsHttpProfile.EventJson
                    ? (await EventsRequestBody.ReadAndVerifyAsync(request, MaxBodyBytes, cancellationToken)
                        .ConfigureAwait(false)).Bytes
                    : await EventsRequestBody.ReadAsync(request, MaxBodyBytes, cancellationToken)
                        .ConfigureAwait(false);
                if (profile == EventsHttpProfile.EventJson &&
                    !request.Content!.Headers.Contains("Content-Digest"))
                    throw Error(EventsVerificationErrorCode.MissingCoveredComponent, "Event profile requires Content-Digest.");
            }
            else if (request.Content is not null)
                throw Error(EventsVerificationErrorCode.UnexpectedCoveredComponent,
                    "Bodyless Events requests must not carry content.");
            return new EventsHttpVerificationResult(profile, parsed.Created, keyHeader, body);
        }
        catch (EventsVerificationException) { throw; }
        catch (FormatException ex)
        {
            throw new EventsVerificationException(
                EventsVerificationErrorCode.MalformedRequest, ex.Message, ex);
        }
    }

    /// <summary>
    /// Resolves the carrier JWT and verifies the request using its bound HTTP key.
    /// </summary>
    public async Task<EventsHttpVerificationResult> VerifyAsync(
        HttpRequestMessage request,
        EventsJwtKeyResolver keyResolver,
        EventsTokenKind tokenKind,
        EventsHttpProfile profile,
        string? expectedAudience = null,
        string? wirePath = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyResolver);
        var resolution = await keyResolver.ResolveRequestAsync(
            request, tokenKind, expectedAudience, cancellationToken).ConfigureAwait(false);
        return await VerifyAsync(
            request, resolution.HttpSignatureKey, profile, wirePath, cancellationToken).ConfigureAwait(false);
    }

    private void CheckFresh(long created)
    {
        var now = Clock().ToUnixTimeSeconds();
        if (created > now + (long)FutureSkew.TotalSeconds)
            throw Error(EventsVerificationErrorCode.InvalidSignature, "Signature created time is in the future.");
        if (created < now - (long)MaxAge.TotalSeconds)
            throw Error(EventsVerificationErrorCode.ExpiredToken, "Signature created time is stale.");
    }

    private static IReadOnlyList<string> Components(EventsHttpProfile profile) =>
        profile switch
        {
            EventsHttpProfile.Bodyless => AAuthEventsConstants.BaseHttpComponents,
            EventsHttpProfile.RegistrationJson => Join(AAuthEventsConstants.BaseHttpComponents,
                AAuthEventsConstants.RegistrationAdditionalHttpComponents),
            EventsHttpProfile.EventJson => Join(AAuthEventsConstants.BaseHttpComponents,
                AAuthEventsConstants.EventAdditionalHttpComponents),
            _ => throw new ArgumentOutOfRangeException(nameof(profile)),
        };

    private static IReadOnlyList<string> Join(IReadOnlyList<string> first, IReadOnlyList<string> second)
    {
        var result = new string[first.Count + second.Count];
        for (var i = 0; i < first.Count; i++) result[i] = first[i];
        for (var i = 0; i < second.Count; i++) result[first.Count + i] = second[i];
        return result;
    }

    private static bool SequenceEqual(IReadOnlyList<string> a, IReadOnlyList<string> b)
    {
        if (a.Count != b.Count) return false;
        for (var i = 0; i < a.Count; i++)
            if (!string.Equals(a[i], b[i], StringComparison.Ordinal)) return false;
        return true;
    }

    private static string BuildSignatureBase(
        HttpRequestMessage request,
        IReadOnlyList<string> components,
        long created,
        string signatureKey,
        string? wirePath)
    {
        if (request.RequestUri is null) throw Error(EventsVerificationErrorCode.MalformedRequest, "Request URI is missing.");
        var path = wirePath ?? "/" + request.RequestUri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
        var authority = request.RequestUri.Authority.ToLowerInvariant();
        var sb = new StringBuilder();
        foreach (var component in components)
        {
            var value = component switch
            {
                "@method" => request.Method.Method.ToUpperInvariant(),
                "@authority" => authority,
                "@path" => path,
                "signature-key" => signatureKey,
                "content-type" => Header(request, "Content-Type"),
                "content-digest" => Header(request, "Content-Digest"),
                _ => throw Error(EventsVerificationErrorCode.UnexpectedCoveredComponent,
                    $"Unsupported covered component '{component}'."),
            };
            sb.Append('"').Append(component).Append("\": ").Append(value).Append('\n');
        }
        sb.Append("\"@signature-params\": (");
        for (var i = 0; i < components.Count; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append('"').Append(components[i]).Append('"');
        }
        sb.Append(");created=").Append(created);
        return sb.ToString();
    }

    private static (IReadOnlyList<string> Components, long Created) ParseSignatureInput(string value)
    {
        var prefix = "sig=(";
        if (!value.StartsWith(prefix, StringComparison.Ordinal))
            throw new FormatException("Signature-Input must contain the sig label.");
        var close = value.IndexOf(')', prefix.Length);
        if (close < 0) throw new FormatException("Signature-Input parameters are unterminated.");
        var list = new List<string>();
        var text = value[prefix.Length..close];
        var pos = 0;
        while (pos < text.Length)
        {
            while (pos < text.Length && text[pos] == ' ') pos++;
            if (pos >= text.Length) break;
            if (text[pos++] != '"') throw new FormatException("Covered components must be quoted.");
            var end = text.IndexOf('"', pos);
            if (end < 0) throw new FormatException("Covered component is unterminated.");
            var name = text[pos..end];
            if (name.Length == 0)
                throw new FormatException("Covered components must be unique and non-empty.");
            list.Add(name);
            pos = end + 1;
        }
        var suffix = value[(close + 1)..];
        const string created = ";created=";
        if (!suffix.StartsWith(created, StringComparison.Ordinal) ||
            !long.TryParse(suffix[created.Length..], out var timestamp))
            throw new FormatException("Signature-Input must contain only a numeric created parameter.");
        return (list, timestamp);
    }

    private static byte[] ParseSignature(string value)
    {
        const string prefix = "sig=:";
        if (!value.StartsWith(prefix, StringComparison.Ordinal) || !value.EndsWith(':'))
            throw new FormatException("Signature must contain one sig byte sequence.");
        try { return Convert.FromBase64String(value[prefix.Length..^1]); }
        catch (FormatException ex) { throw new FormatException("Signature is not valid base64.", ex); }
    }

    private static string SingleHeader(HttpRequestMessage request, string name)
    {
        if (!request.Headers.TryGetValues(name, out var values))
            throw new FormatException($"Header '{name}' must occur exactly once.");
        using var enumerator = values.GetEnumerator();
        if (!enumerator.MoveNext()) throw new FormatException($"Header '{name}' must occur exactly once.");
        var current = enumerator.Current;
        if (current is null || enumerator.MoveNext())
            throw new FormatException($"Header '{name}' must occur exactly once.");
        return current;
    }

    private static string Header(HttpRequestMessage request, string name)
    {
        if (request.Content?.Headers.TryGetValues(name, out var content) == true)
            return string.Join(", ", content);
        if (request.Headers.TryGetValues(name, out var headers))
            return string.Join(", ", headers);
        throw Error(EventsVerificationErrorCode.MissingCoveredComponent, $"Header '{name}' is missing.");
    }

    private static void RequireJson(HttpRequestMessage request)
    {
        var type = Header(request, "Content-Type").Split(';', 2)[0].Trim();
        if (!string.Equals(type, AAuthEventsConstants.JsonMediaType, StringComparison.Ordinal))
            throw Error(EventsVerificationErrorCode.MalformedRequest, "Events body must use application/json.");
    }

    private static void RejectForbidden(HttpRequestMessage request)
    {
        if (request.Headers.Authorization is not null ||
            request.Headers.Contains("Authorization") ||
            request.Headers.Contains("AAuth-Mission"))
            throw Error(EventsVerificationErrorCode.UnexpectedCoveredComponent,
                "Authorization and AAuth-Mission are not Events profile components.");
    }

    private static byte[] ParseSignatureValue(string value) => ParseSignature(value);

    private static EventsVerificationException Error(EventsVerificationErrorCode code, string detail) =>
        new(code, detail);
}

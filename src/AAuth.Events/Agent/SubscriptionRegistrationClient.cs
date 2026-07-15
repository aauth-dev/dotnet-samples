using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using AAuth.Crypto;
using AAuth.Events.Http;

namespace AAuth.Events.Agent;

/// <summary>Result returned by a resource subscription registration endpoint.</summary>
public sealed record SubscriptionRegistrationClientResult(
    HttpStatusCode StatusCode,
    IReadOnlyList<string> SelectedEventTypes,
    string? ResponseBody);

/// <summary>Exception raised when registration transport or status handling fails.</summary>
public sealed class SubscriptionRegistrationClientException : HttpRequestException
{
    /// <summary>Creates a typed registration client failure.</summary>
    public SubscriptionRegistrationClientException(
        string message, HttpStatusCode? statusCode = null, string? responseBody = null, Exception? inner = null)
        : base(message, inner, statusCode)
    {
        ResponseBody = responseBody;
    }

    /// <summary>Response body, when one was available.</summary>
    public string? ResponseBody { get; }
}

/// <summary>
/// Signs subscription POSTs with the subscribe token as the sole
/// <c>Signature-Key</c> credential and the agent confirmation private key.
/// </summary>
public sealed class SubscriptionRegistrationClient
{
    private readonly HttpClient _http;
    private readonly IAAuthKey _confirmationKey;
    private readonly string? _token;
    private readonly Func<DateTimeOffset>? _clock;

    /// <summary>Creates a client with a token supplied to each call.</summary>
    public SubscriptionRegistrationClient(
        HttpClient http,
        IAAuthKey confirmationKey,
        Func<DateTimeOffset>? clock = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _confirmationKey = confirmationKey ?? throw new ArgumentNullException(nameof(confirmationKey));
        if (!_confirmationKey.HasPrivateKey)
            throw new ArgumentException("The confirmation key must include a private component.", nameof(confirmationKey));
        if (_confirmationKey.Algorithm is not "EdDSA" and not "ES256")
            throw new ArgumentException("The confirmation key algorithm must be EdDSA or ES256.", nameof(confirmationKey));
        _clock = clock;
    }

    /// <summary>Creates a client with a fixed subscribe token.</summary>
    public SubscriptionRegistrationClient(
        HttpClient http,
        string subscribeToken,
        IAAuthKey confirmationKey,
        Func<DateTimeOffset>? clock = null)
        : this(http, confirmationKey, clock)
    {
        if (string.IsNullOrWhiteSpace(subscribeToken)) throw new ArgumentException("A subscribe token is required.", nameof(subscribeToken));
        _token = subscribeToken;
    }

    /// <summary>Sends a bodyless or JSON registration request.</summary>
    public Task<SubscriptionRegistrationClientResult> RegisterAsync(
        Uri endpoint,
        string subscribeToken,
        byte[]? body = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(endpoint, subscribeToken, body, cancellationToken);

    /// <summary>Sends using the token supplied to the constructor.</summary>
    public Task<SubscriptionRegistrationClientResult> RegisterAsync(
        Uri endpoint,
        byte[]? body = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(endpoint, _token ?? throw new InvalidOperationException("No subscribe token was supplied."), body, cancellationToken);

    /// <summary>Sends a JSON registration with exact UTF-8 bytes.</summary>
    public Task<SubscriptionRegistrationClientResult> RegisterJsonAsync(
        Uri endpoint,
        string subscribeToken,
        string json,
        CancellationToken cancellationToken = default) =>
        SendAsync(endpoint, subscribeToken, Encoding.UTF8.GetBytes(json ?? throw new ArgumentNullException(nameof(json))), cancellationToken);

    /// <summary>Alias for <see cref="RegisterAsync(Uri,string,byte[],CancellationToken)"/>.</summary>
    public Task<SubscriptionRegistrationClientResult> PostAsync(
        Uri endpoint,
        string subscribeToken,
        byte[]? body = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(endpoint, subscribeToken, body, cancellationToken);

    private async Task<SubscriptionRegistrationClientResult> SendAsync(
        Uri endpoint,
        string subscribeToken,
        byte[]? body,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (string.IsNullOrWhiteSpace(subscribeToken)) throw new ArgumentException("A subscribe token is required.", nameof(subscribeToken));
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.TryAddWithoutValidation("Content-Type", AAuthEventsConstants.JsonMediaType);
        }
        var signer = new EventsRequestSigner(
            _confirmationKey,
            () => subscribeToken,
            _clock);
        if (body is null) signer.SignBodyless(request);
        else signer.SignRegistration(request);

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (HttpRequestException) { throw; }

        using (response)
        {
            var text = response.Content is null
                ? null
                : await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if ((int)response.StatusCode is < 200 or >= 300)
                throw new SubscriptionRegistrationClientException(
                    $"Registration endpoint returned {(int)response.StatusCode}.",
                    response.StatusCode, text);
            var selected = ParseSelectedTypes(text);
            return new SubscriptionRegistrationClientResult(response.StatusCode, selected, text);
        }
    }

    private static IReadOnlyList<string> ParseSelectedTypes(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return Array.Empty<string>();
        try
        {
            using var document = JsonDocument.Parse(text);
            if (!document.RootElement.TryGetProperty("event_types", out var types) ||
                types.ValueKind != JsonValueKind.Array)
                return Array.Empty<string>();
            return types.EnumerateArray().Where(static item => item.ValueKind == JsonValueKind.String)
                .Select(static item => item.GetString()!).ToArray();
        }
        catch (JsonException ex)
        {
            throw new SubscriptionRegistrationClientException("Registration response is malformed JSON.", responseBody: text, inner: ex);
        }
    }
}

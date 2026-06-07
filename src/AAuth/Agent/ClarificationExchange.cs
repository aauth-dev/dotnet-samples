using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// The action an agent chooses in response to a clarification question
/// (AAuth protocol §Agent Response to Clarification). One of: a
/// <see cref="Respond"/> (answer the question), an <see cref="Update"/>
/// (replace the request with a new resource token), or a <see cref="Cancel"/>
/// (withdraw the request).
/// </summary>
public sealed class ClarificationResponse
{
    /// <summary>The kind of response.</summary>
    public enum Kind
    {
        /// <summary>Answer the question with a Markdown explanation.</summary>
        Respond,

        /// <summary>Replace the request with an updated resource token.</summary>
        Update,

        /// <summary>Withdraw the request entirely.</summary>
        Cancel,
    }

    /// <summary>Which action this response represents.</summary>
    public Kind Action { get; }

    /// <summary>The Markdown answer (for <see cref="Kind.Respond"/>).</summary>
    public string? Markdown { get; }

    /// <summary>The replacement resource token (for <see cref="Kind.Update"/>).</summary>
    public string? ResourceToken { get; }

    /// <summary>Optional justification for an updated request.</summary>
    public string? Justification { get; }

    private ClarificationResponse(Kind action, string? markdown, string? resourceToken, string? justification)
    {
        Action = action;
        Markdown = markdown;
        ResourceToken = resourceToken;
        Justification = justification;
    }

    /// <summary>Answer the clarification with a Markdown explanation.</summary>
    public static ClarificationResponse Respond(string markdown)
    {
        ArgumentException.ThrowIfNullOrEmpty(markdown);
        return new ClarificationResponse(Kind.Respond, markdown, null, null);
    }

    /// <summary>
    /// Replace the original request with a new resource token (e.g. reduced
    /// scope). A <paramref name="justification"/> is optional but RECOMMENDED.
    /// </summary>
    public static ClarificationResponse Update(string resourceToken, string? justification = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);
        return new ClarificationResponse(Kind.Update, null, resourceToken, justification);
    }

    /// <summary>Withdraw the request.</summary>
    public static ClarificationResponse Cancel()
        => new(Kind.Cancel, null, null, null);
}

/// <summary>
/// Drives the agent side of a clarification chat against a deferred-response
/// pending URL (AAuth protocol §Agent Response to Clarification): posting a
/// clarification response, posting an updated request, or cancelling. Tracks
/// the number of rounds and enforces a maximum (§Clarification Limits).
/// </summary>
/// <remarks>
/// The supplied <see cref="HttpClient"/> is expected to be wired with the
/// agent's <see cref="HttpSig.AAuthSigningHandler"/> so each POST/DELETE to
/// the pending URL is signed — the PS rejects otherwise.
/// </remarks>
public sealed class ClarificationExchange
{
    /// <summary>Spec-recommended default maximum clarification rounds.</summary>
    public const int DefaultMaxRounds = 5;

    private readonly HttpClient _signedClient;
    private readonly Uri _pendingUrl;

    /// <summary>The maximum number of clarification rounds permitted.</summary>
    public int MaxRounds { get; }

    /// <summary>The number of clarification rounds consumed so far.</summary>
    public int Rounds { get; private set; }

    /// <summary>Create a clarification exchange bound to a pending URL.</summary>
    /// <param name="signedClient">HttpClient pre-wired with the agent's signing handler.</param>
    /// <param name="pendingUrl">Absolute pending URL (the deferred <c>Location</c> value).</param>
    /// <param name="maxRounds">Maximum clarification rounds (default 5).</param>
    public ClarificationExchange(HttpClient signedClient, Uri pendingUrl, int maxRounds = DefaultMaxRounds)
    {
        ArgumentNullException.ThrowIfNull(signedClient);
        ArgumentNullException.ThrowIfNull(pendingUrl);
        if (!pendingUrl.IsAbsoluteUri)
        {
            throw new ArgumentException("Pending URL must be absolute.", nameof(pendingUrl));
        }
        if (maxRounds < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRounds), "Max rounds must be at least 1.");
        }
        _signedClient = signedClient;
        _pendingUrl = pendingUrl;
        MaxRounds = maxRounds;
    }

    /// <summary>
    /// Apply <paramref name="response"/> to the pending URL. Returns
    /// <see langword="true"/> when the agent should resume polling (respond or
    /// update), or throws <see cref="Errors.AAuthMissionTerminatedException"/>-style
    /// terminal exceptions where appropriate. A cancel throws
    /// <see cref="AAuthClarificationCancelledException"/> after withdrawing.
    /// </summary>
    public async Task ApplyAsync(ClarificationResponse response, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        switch (response.Action)
        {
            case ClarificationResponse.Kind.Respond:
                await RespondAsync(response.Markdown!, cancellationToken).ConfigureAwait(false);
                break;
            case ClarificationResponse.Kind.Update:
                await UpdateRequestAsync(response.ResourceToken!, response.Justification, cancellationToken)
                    .ConfigureAwait(false);
                break;
            case ClarificationResponse.Kind.Cancel:
                await CancelAsync(cancellationToken).ConfigureAwait(false);
                throw new AAuthClarificationCancelledException(
                    "The agent withdrew its request during clarification.");
            default:
                throw new ArgumentOutOfRangeException(nameof(response));
        }
    }

    /// <summary>POST a Markdown clarification response to the pending URL.</summary>
    public async Task RespondAsync(string markdown, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(markdown);
        EnterRound();
        var body = new JsonObject { ["clarification_response"] = markdown };
        await PostAsync(body, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>POST an updated resource token (and optional justification) to the pending URL.</summary>
    public async Task UpdateRequestAsync(
        string resourceToken, string? justification = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);
        EnterRound();
        var body = new JsonObject { ["resource_token"] = resourceToken };
        if (!string.IsNullOrEmpty(justification))
        {
            body["justification"] = justification;
        }
        await PostAsync(body, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>DELETE the pending URL to withdraw the request.</summary>
    public async Task CancelAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, _pendingUrl);
        using var response = await _signedClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    private void EnterRound()
    {
        if (Rounds >= MaxRounds)
        {
            throw new AAuthClarificationLimitException(MaxRounds);
        }
        Rounds++;
    }

    private async Task PostAsync(JsonObject body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, _pendingUrl)
        {
            Content = JsonContent.Create(body),
        };
        using var response = await _signedClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }
}

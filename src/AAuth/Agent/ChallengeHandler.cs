using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.CallChaining;

namespace AAuth.Agent;

/// <summary>
/// <see cref="DelegatingHandler"/> that auto-handles AAuth 401 challenges.
/// On a <c>401</c> with <c>AAuth-Requirement: requirement=auth-token</c>,
/// extracts the resource token, exchanges it at the agent's PS, swaps the
/// carrier token in the shared <see cref="AAuthTokenHolder"/>, and retries
/// the original request once.
/// </summary>
/// <remarks>
/// Sits <em>above</em> <see cref="HttpSig.AAuthSigningHandler"/> in the
/// handler chain so the retry re-signs through the same pipeline. The
/// signing handler reads the carrier token via the holder, so a single
/// pipeline transparently transitions from agent-token to auth-token
/// signing across the challenge. The exchange itself runs through a
/// <em>separate</em> signed pipeline configured by the caller — it must
/// always sign with the agent token, never with the (not-yet-issued) auth
/// token. See <see cref="TokenExchangeClient"/>.
/// </remarks>
public sealed class ChallengeHandler : DelegatingHandler
{
    private readonly TokenExchangeClient _exchange;
    private readonly AAuthTokenHolder _holder;
    private readonly string? _personServer;
    private readonly Func<Interaction, CancellationToken, Task>? _onInteractionRequired;
    private readonly DeferredPollerOptions? _pollerOptions;
    private readonly Func<string?>? _upstreamTokenProvider;

    // Per-origin cache of additional signature components a resource has been
    // observed to require (learned from an `invalid_input` + `required_input`
    // 401, or seeded from resource metadata via AdditionalSignatureComponents).
    // Keyed by origin (scheme://host:port). Once learned, subsequent requests
    // to that origin proactively include the components so they sign correctly
    // on the first attempt. §Covered Components.
    private readonly ConcurrentDictionary<string, IReadOnlyList<string>> _learnedComponents
        = new(StringComparer.Ordinal);

    /// <summary>Create the challenge handler.</summary>
    /// <param name="exchange">Token exchange client (configured with the agent token).</param>
    /// <param name="holder">Shared carrier-token holder used by the signer.</param>
    /// <param name="personServer">PS issuer URL where resource tokens are exchanged.</param>
    /// <param name="onInteractionRequired">
    /// Optional callback invoked when the PS returns <c>202 + requirement=interaction</c>
    /// during the embedded exchange. Hosts wire this to "display URL to user" UI.
    /// When <see langword="null"/>, a deferred PS response surfaces as an exception.
    /// </param>
    /// <param name="pollerOptions">Optional polling cadence/timeout override.</param>
    public ChallengeHandler(
        TokenExchangeClient exchange,
        AAuthTokenHolder holder,
        string personServer,
        Func<Interaction, CancellationToken, Task>? onInteractionRequired = null,
        DeferredPollerOptions? pollerOptions = null)
        : this(exchange, holder, personServer, onInteractionRequired, pollerOptions,
               upstreamTokenProvider: null)
    {
    }

    /// <summary>Create the challenge handler with call-chaining support.</summary>
    /// <param name="exchange">Token exchange client (configured with the agent token).</param>
    /// <param name="holder">Shared carrier-token holder used by the signer.</param>
    /// <param name="personServer">
    /// PS issuer URL. Nullable when <paramref name="upstreamTokenProvider"/> is supplied
    /// (routing determined from upstream token). At least one must be non-null.
    /// </param>
    /// <param name="onInteractionRequired">Optional interaction callback.</param>
    /// <param name="pollerOptions">Optional polling cadence/timeout override.</param>
    /// <param name="upstreamTokenProvider">
    /// When supplied, the handler uses <see cref="CallChainingRouter"/> to resolve
    /// the downstream PS/AS from the upstream auth token. Takes precedence over
    /// <paramref name="personServer"/> when the provider returns a non-null value.
    /// </param>
    public ChallengeHandler(
        TokenExchangeClient exchange,
        AAuthTokenHolder holder,
        string? personServer,
        Func<Interaction, CancellationToken, Task>? onInteractionRequired,
        DeferredPollerOptions? pollerOptions,
        Func<string?>? upstreamTokenProvider)
    {
        ArgumentNullException.ThrowIfNull(exchange);
        ArgumentNullException.ThrowIfNull(holder);

        if (personServer is null && upstreamTokenProvider is null)
            throw new ArgumentException(
                "At least one of personServer or upstreamTokenProvider must be supplied.");

        _exchange = exchange;
        _holder = holder;
        _personServer = personServer;
        _onInteractionRequired = onInteractionRequired;
        _pollerOptions = pollerOptions;
        _upstreamTokenProvider = upstreamTokenProvider;
    }

    /// <summary>
    /// Capabilities to declare to the PS during the embedded exchange.
    /// When <see langword="null"/> (default), capabilities are inferred from
    /// the flow (<c>"interaction"</c> when an interaction callback is wired).
    /// An explicit (possibly empty) list overrides inference.
    /// </summary>
    public IReadOnlyList<string>? Capabilities { get; init; }

    /// <summary>
    /// Optional OIDC <c>prompt</c> value sent to the PS during the embedded
    /// exchange (e.g. <c>"consent"</c>). When <see langword="null"/> (default),
    /// no <c>prompt</c> is sent.
    /// </summary>
    public string? Prompt { get; init; }

    /// <summary>
    /// Optional callback invoked when the PS returns <c>202 + requirement=clarification</c>
    /// during the embedded exchange (§Clarification Chat). The callback answers the
    /// question (respond / update / cancel); when set, the agent declares the
    /// <c>clarification</c> capability. When <see langword="null"/> and the PS asks for
    /// clarification, the exchange throws.
    /// </summary>
    public Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>>? OnClarificationRequired { get; init; }

    /// <summary>
    /// Maximum number of clarification rounds before the embedded exchange aborts
    /// (§Clarification Chat). Default: 5.
    /// </summary>
    public int MaxClarificationRounds { get; init; } = ClarificationExchange.DefaultMaxRounds;

    /// <summary>
    /// Additional signature components a resource requires, keyed by origin
    /// (<c>scheme://host:port</c>), typically discovered from the resource's
    /// <c>additional_signature_components</c> metadata. When set, requests to
    /// a matching origin proactively cover those components on the first
    /// attempt. Components additionally learned at runtime from an
    /// <c>invalid_input</c> error are merged on top of these. §Covered
    /// Components.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? AdditionalSignatureComponents { get; init; }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await SendWithAdaptiveSigningAsync(request, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        if (!response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values))
        {
            return response;
        }

        AAuthRequirementHeader.ParsedRequirement? requirement = null;
        // The header MAY appear more than once; parse each value
        // independently and pick the first auth-token requirement we
        // recognise. Concatenating with ',' and re-parsing would only work
        // if AAuthRequirementHeader.Parse spoke full RFC 9651 dictionary
        // grammar, which it deliberately doesn't.
        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw)) { continue; }
            try
            {
                var candidate = AAuthRequirementHeader.Parse(raw);

                // §Agent Token Required: a bare requirement=agent-token asks for
                // the agent's own identity token — no PS/AS, no resource token to
                // exchange. The SDK already signs every request with the agent
                // token via the shared holder, so the agent token is being
                // presented; there is nothing to exchange. Skip it (and never let
                // a stray resource-token param turn it into an exchange).
                if (candidate.Requirement == AAuthRequirementHeader.AgentTokenRequirement)
                {
                    continue;
                }

                if (candidate.Requirement == AAuthRequirementHeader.AuthTokenRequirement
                    && candidate.ResourceToken is not null)
                {
                    requirement = candidate;
                    break;
                }
            }
            catch (FormatException)
            {
                // Skip malformed individual values; another header line may
                // still carry a usable requirement.
            }
        }

        if (requirement is null)
        {
            return response;
        }

        // Got an auth-token challenge. Exchange and retry.
        using var activity = AAuthDiagnostics.Source.StartActivity("AAuth.ChallengeExchange");

        var upstreamToken = _upstreamTokenProvider?.Invoke();
        var targetServer = upstreamToken is not null
            ? CallChainingRouter.ResolveDownstreamServer(upstreamToken)
            : _personServer
                ?? throw new InvalidOperationException(
                    "No personServer configured and upstreamTokenProvider returned null.");

        var authToken = await _exchange
            .ExchangeAsync(targetServer, requirement.ResourceToken!,
                new TokenExchangeRequest
                {
                    OnInteractionRequired = _onInteractionRequired,
                    PollerOptions = _pollerOptions,
                    UpstreamToken = upstreamToken,
                    Capabilities = Capabilities,
                    Prompt = Prompt,
                    OnClarificationRequired = OnClarificationRequired,
                    MaxClarificationRounds = MaxClarificationRounds,
                },
                cancellationToken)
            .ConfigureAwait(false);
        _holder.Update(authToken);

        // Clone the original request to retry — HttpRequestMessage is
        // single-use, and the signing handler downstream will re-sign with
        // the new carrier token (read via the holder) when the clone is
        // sent. Note: the original request body, if any, is forwarded
        // verbatim; streaming bodies that are not re-readable will fail
        // here, which is a known limitation.
        response.Dispose();
        var retry = await CloneAsync(request, cancellationToken).ConfigureAwait(false);
        var result = await SendWithAdaptiveSigningAsync(retry, cancellationToken).ConfigureAwait(false);
        // Reassign the response's RequestMessage to the caller-owned
        // original so diagnostics (EnsureSuccessStatusCode, loggers) keep
        // working, then dispose the short-lived clone. This avoids both
        // (a) retaining the cloned ByteArrayContent on the response until
        // GC and (b) handing callers a response backed by a disposed
        // request — the trade-off of the previous `using` placement.
        result.RequestMessage = request;
        retry.Dispose();
        return result;
    }

    // Send a request through the inner pipeline, transparently handling the
    // adaptive-signing handshake: seed any known additional components into
    // the request so the signer covers them, and on a `401` carrying
    // `Signature-Error: invalid_input; required_input="..."`, learn the
    // required components, re-sign, and retry exactly once. §Covered
    // Components / §Verification step 2.
    private async Task<HttpResponseMessage> SendWithAdaptiveSigningAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        SeedAdditionalComponents(request);

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.Unauthorized
            || request.RequestUri is null
            || !response.Headers.TryGetValues(SignatureError.HeaderName, out var errorValues))
        {
            return response;
        }

        string? rawError = null;
        foreach (var value in errorValues)
        {
            if (!string.IsNullOrWhiteSpace(value)) { rawError = value; break; }
        }

        if (rawError is null
            || !SignatureError.TryParse(rawError, out var code)
            || code != SignatureErrorCode.InvalidInput)
        {
            return response;
        }

        var required = SignatureError.ParseRequiredInput(rawError);
        if (required.Length == 0)
        {
            return response;
        }

        // Learn the components for this origin (additive: base components and
        // anything previously learned are preserved), then re-sign and retry
        // exactly once. AddOrUpdate keeps concurrent 401s for the same origin
        // from clobbering each other (each produces a superset).
        var origin = GetOrigin(request.RequestUri);
        var merged = _learnedComponents.AddOrUpdate(
            origin,
            _ => MergeComponents(origin, required),
            (_, _) => MergeComponents(origin, required));

        response.Dispose();
        var retry = await CloneAsync(request, cancellationToken).ConfigureAwait(false);
        retry.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, merged);
        var result = await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
        result.RequestMessage = request;
        retry.Dispose();
        return result;
    }

    // Seed the request with this origin's known additional components (learned
    // at runtime or seeded from metadata) so the signer covers them.
    private void SeedAdditionalComponents(HttpRequestMessage request)
    {
        if (request.RequestUri is null)
        {
            return;
        }

        var origin = GetOrigin(request.RequestUri);
        var hasLearnedOrSeeded =
            _learnedComponents.ContainsKey(origin)
            || AdditionalSignatureComponents?.ContainsKey(origin) == true;
        if (!hasLearnedOrSeeded)
        {
            // Nothing to seed for this origin; leave any caller-set
            // components on the request untouched.
            return;
        }

        // Merge metadata-seeded + learned components with any components the
        // caller already set on the request (additive, order-preserving,
        // de-duplicated) so a per-request AdditionalComponentsKey value is
        // never clobbered.
        request.Options.TryGetValue(AAuthSigningHandler.AdditionalComponentsKey, out var callerSet);
        var merged = MergeComponents(origin, callerSet ?? Array.Empty<string>());
        if (merged.Count > 0)
        {
            request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, merged);
        }
    }

    // Combine metadata-seeded components, previously learned components, and
    // the newly required ones into a de-duplicated, order-preserving list.
    private IReadOnlyList<string> MergeComponents(string origin, IEnumerable<string> required)
    {
        var ordered = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Add(IEnumerable<string>? source)
        {
            if (source is null) { return; }
            foreach (var item in source)
            {
                if (string.IsNullOrWhiteSpace(item)) { continue; }
                var name = item.Trim();
                if (seen.Add(name)) { ordered.Add(name); }
            }
        }

        if (AdditionalSignatureComponents?.TryGetValue(origin, out var seeded) == true)
        {
            Add(seeded);
        }
        if (_learnedComponents.TryGetValue(origin, out var learned))
        {
            Add(learned);
        }
        Add(required);

        return ordered;
    }

    private static string GetOrigin(Uri uri)
        => uri.GetComponents(
                UriComponents.Scheme | UriComponents.Host | UriComponents.Port,
                UriFormat.UriEscaped)
            .ToLowerInvariant();

    private static async Task<HttpRequestMessage> CloneAsync(
        HttpRequestMessage source, CancellationToken cancellationToken)
    {
        var clone = new HttpRequestMessage(source.Method, source.RequestUri)
        {
            Version = source.Version,
            VersionPolicy = source.VersionPolicy,
        };

        if (source.Content is not null)
        {
            var bytes = await source.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            var content = new ByteArrayContent(bytes);
            foreach (var header in source.Content.Headers)
            {
                content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            clone.Content = content;
        }

        foreach (var header in source.Headers)
        {
            // Strip prior signature headers so the signer re-emits them.
            if (header.Key is AAuthConstants.Headers.Signature or AAuthConstants.Headers.SignatureInput or AAuthConstants.Headers.SignatureKey)
            {
                continue;
            }
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        // Carry request-scoped options onto the clone so caller state (a
        // per-request AdditionalComponentsKey, telemetry/Polly context, etc.)
        // survives the retry. AAuth-specific keys are re-applied downstream
        // (SeedAdditionalComponents / the adaptive retry), but copying here
        // preserves anything else the caller attached. HttpRequestOptions
        // exposes IDictionary<string, object?> for writes.
        foreach (var option in source.Options)
        {
            ((IDictionary<string, object?>)clone.Options)[option.Key] = option.Value;
        }

        return clone;
    }
}

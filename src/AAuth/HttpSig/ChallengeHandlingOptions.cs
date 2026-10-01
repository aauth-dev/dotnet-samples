using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Headers;

namespace AAuth.HttpSig;

/// <summary>
/// Options for configuring challenge handling on <see cref="AAuthClientBuilder"/>.
/// </summary>
public sealed class ChallengeHandlingOptions
{
    /// <summary>
    /// Optional callback invoked when the PS returns <c>202 + requirement=interaction</c>
    /// during token exchange. The caller should display the interaction URL to the user.
    /// When <see langword="null"/>, a deferred PS response surfaces as an exception.
    /// </summary>
    public Func<Interaction, CancellationToken, Task>? OnInteractionRequired { get; set; }

    /// <summary>
    /// Optional callback invoked when the PS returns <c>202 + requirement=clarification</c>
    /// during token exchange (§Clarification Chat). The callback receives the parsed
    /// question and returns the agent's chosen <see cref="ClarificationResponse"/>
    /// (respond / update / cancel), which the exchange applies before resuming polling.
    /// When set, the agent declares the <c>clarification</c> capability to the PS; when
    /// <see langword="null"/> and the PS asks for clarification, the exchange throws.
    /// </summary>
    public Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>>? OnClarificationRequired { get; set; }

    /// <summary>
    /// Maximum number of clarification rounds the agent will engage in before
    /// giving up (§Clarification Chat). Default: 5.
    /// </summary>
    public int MaxClarificationRounds { get; set; } = ClarificationExchange.DefaultMaxRounds;

    /// <summary>
    /// Maximum time to poll a deferred PS response before timing out.
    /// Default: 5 minutes.
    /// </summary>
    public TimeSpan PollingTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Default poll interval when no <c>Retry-After</c> header is present.
    /// Per spec, default is 5 seconds.
    /// </summary>
    public TimeSpan DefaultPollInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// When set, sends a <c>Prefer: wait=N</c> header on each poll request,
    /// signalling to the server that the client is willing to long-poll for
    /// up to N seconds. Per RFC 7240 §4.3. When <see langword="null"/>
    /// (default), no <c>Prefer</c> header is sent.
    /// </summary>
    public int? PreferWaitSeconds { get; set; }

    /// <summary>
    /// Minimum delay between polls regardless of server's <c>Retry-After</c>.
    /// Default: zero, so <c>Retry-After: 0</c> is immediate.
    /// </summary>
    public TimeSpan MinPollInterval { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Optional callback invoked after each poll response. Useful for logging
    /// or progress UI during deferred exchanges.
    /// </summary>
    public Action<System.Net.Http.HttpResponseMessage>? OnPoll { get; set; }

    /// <summary>
    /// Capabilities to declare to the PS in the token request body. When
    /// <see langword="null"/> (default), capabilities are inferred from the
    /// flow: <c>"interaction"</c> is declared when <see cref="OnInteractionRequired"/>
    /// is set. Supply an explicit (possibly empty) list to override inference —
    /// an empty list suppresses the capability declaration entirely.
    /// </summary>
    public System.Collections.Generic.IList<string>? Capabilities { get; set; }

    /// <summary>
    /// Optional OIDC <c>prompt</c> value (e.g. <c>"consent"</c>, <c>"login"</c>,
    /// <c>"none"</c>, <c>"select_account"</c>) sent to the PS during token
    /// exchange to influence the consent/login experience. When
    /// <see langword="null"/> (default), no <c>prompt</c> is sent.
    /// </summary>
    public string? Prompt { get; set; }

    /// <summary>
    /// Additional signature components a resource requires, keyed by origin
    /// (<c>scheme://host:port</c>). Typically populated from a resource's
    /// <c>additional_signature_components</c> metadata so requests cover those
    /// components on the first attempt. Components a resource demands at
    /// runtime via an <c>invalid_input</c> error are learned and merged on top
    /// of these automatically, so this is an optional optimisation.
    /// §Covered Components.
    /// </summary>
    public System.Collections.Generic.IReadOnlyDictionary<string,
        System.Collections.Generic.IReadOnlyList<string>>? AdditionalSignatureComponents { get; set; }

    /// <summary>
    /// Seed first-request signing from parsed resource metadata. The resource
    /// <c>issuer</c> supplies the origin key and
    /// <c>additional_signature_components</c> supplies the components.
    /// </summary>
    /// <param name="metadata">Parsed resource metadata.</param>
    /// <returns>This options instance for fluent configuration.</returns>
    public ChallengeHandlingOptions AddResourceMetadata(ResourceMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (metadata.AdditionalSignatureComponents is not { Count: > 0 })
        {
            return this;
        }
        if (!Uri.TryCreate(metadata.Issuer, UriKind.Absolute, out var issuer))
        {
            throw new InvalidOperationException("Resource metadata issuer must be an absolute URI.");
        }

        var origin = issuer.GetComponents(
                UriComponents.Scheme | UriComponents.Host | UriComponents.Port,
                UriFormat.UriEscaped)
            .ToLowerInvariant();
        var merged = new Dictionary<string, IReadOnlyList<string>>(
            AdditionalSignatureComponents ?? new Dictionary<string, IReadOnlyList<string>>(),
            StringComparer.OrdinalIgnoreCase);
        merged[origin] = Merge(metadata.AdditionalSignatureComponents,
            merged.TryGetValue(origin, out var existing) ? existing : null);
        AdditionalSignatureComponents = merged;
        return this;
    }

    private static IReadOnlyList<string> Merge(
        IEnumerable<string> metadataComponents, IEnumerable<string>? existingComponents)
    {
        var merged = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(IEnumerable<string>? components)
        {
            if (components is null)
            {
                return;
            }
            foreach (var raw in components)
            {
                if (string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }
                var component = raw.Trim().ToLowerInvariant();
                if (seen.Add(component))
                {
                    merged.Add(component);
                }
            }
        }

        Add(metadataComponents);
        Add(existingComponents);
        return merged;
    }
}

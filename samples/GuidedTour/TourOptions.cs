namespace GuidedTour;

/// <summary>
/// Which protocol flow the tour walks through.
/// <see cref="Identity"/> renders the 4-step identity-based path where
/// the resource trusts the agent token directly and no Person Server is
/// involved. <see cref="Autonomous"/> renders the 8-step three-party
/// "happy path" where the PS issues an auth token immediately.
/// <see cref="Deferred"/> renders the 11-step user-consent path:
/// exchange returns 202, the agent surfaces an interaction URL to its
/// user, the user approves, and the agent polls until the PS mints the
/// auth token.
/// </summary>
public enum TourMode
{
    Bootstrap,
    Identity,
    Autonomous,
    Deferred,
}

/// <summary>
/// Which Signature-Key scheme the agent uses for signed requests.
/// Maps 1:1 to the four AAuth signing modes.
/// </summary>
public enum SigningMode
{
    /// <summary><c>sig=jwt</c> — carry agent/auth token inline (default).</summary>
    Jwt,
    /// <summary><c>sig=hwk</c> — pseudonymous, bare key thumbprint.</summary>
    Hwk,
    /// <summary><c>sig=jwks_uri</c> — agent identity via discoverable JWKS.</summary>
    JwksUri,
    /// <summary><c>sig=jkt-jwt</c> — two-key delegation (durable → ephemeral).</summary>
    JktJwt,
}

/// <summary>
/// Configuration for the Guided Tour sample. Bound from the
/// <c>GuidedTour</c> section of <c>appsettings.json</c>.
/// </summary>
public sealed class TourOptions
{
    /// <summary>Base URL of the WhoAmI resource server.</summary>
    public string WhoAmIUrl { get; set; } = "http://localhost:5000";

    /// <summary>
    /// Optional MockPersonServer URL. When set, the tour walks one of the
    /// three-party flows (selected by <see cref="Mode"/>); when null/empty
    /// the tour falls back to identity-based mode (4 steps), regardless
    /// of <see cref="Mode"/>.
    /// </summary>
    public string? PersonServerUrl { get; set; }

    /// <summary>Agent identifier embedded in the agent token's <c>sub</c>.</summary>
    public string AgentId { get; set; } = "aauth:tour-agent@ap.example";

    /// <summary>
    /// Optional Agent Provider base URL. When set, the bootstrap flow
    /// discovers the AP's <c>enrol_endpoint</c> from its well-known
    /// metadata and enrols with the real AP (e.g. http://localhost:5301)
    /// instead of building a self-signed token locally.
    /// </summary>
    public string? AgentProviderUrl { get; set; }

    /// <summary>
    /// Which flow to walk by default when the page loads. Defaults to
    /// <see cref="TourMode.Bootstrap"/>; the user can flip to other
    /// modes via the in-page picker. When <see cref="PersonServerUrl"/>
    /// is empty, the tour forces <see cref="TourMode.Identity"/>
    /// regardless of this setting.
    /// </summary>
    public TourMode Mode { get; set; } = TourMode.Bootstrap;
}


namespace GuidedTour;

/// <summary>
/// Which protocol flow the tour walks through.
/// <see cref="Identity"/> renders the 4-step identity-based path where
/// the resource trusts the agent token directly and no Person Server is
/// involved. <see cref="ResourceManaged"/> renders the 6-step two-party
/// AAuth-Access path: the resource manages authorization itself via its
/// own consent page and hands back an opaque token the agent replays
/// (no Person Server, no token exchange). <see cref="Autonomous"/> renders
/// the 8-step three-party "happy path" where the PS issues an auth token
/// immediately. <see cref="Deferred"/> renders the 11-step user-consent
/// path: exchange returns 202, the agent surfaces an interaction URL to its
/// user, the user approves, and the agent polls until the PS mints the
/// auth token.
/// </summary>
public enum TourMode
{
    Bootstrap,
    Identity,
    ResourceManaged,
    Autonomous,
    Deferred,
    CallChain,
    Federated,
    Mission,
    MissionCallChain,
    SubAgent,
}

/// <summary>
/// Which Signature-Key scheme the agent uses for resource requests.
/// These map to the AAuth signing modes defined in the HTTP Signature Keys
/// specification. Three-party flows (Autonomous/Deferred) MUST use
/// <see cref="Jwt"/> per spec (requires a PS-issued token); identity-based
/// access (no PS) uses <see cref="Hwk"/> or <see cref="JwksUri"/>.
/// </summary>
public enum SigningMode
{
    /// <summary>
    /// <c>sig=jwt</c> — Agent Token mode. The full agent token (or auth
    /// token) travels inline. Resource learns: agent identity, PS URL,
    /// bound signing key. Requires a Person Server; used in three-party flows.
    /// </summary>
    Jwt,
    /// <summary>
    /// <c>sig=hwk</c> — Pseudonymous mode. The full public key is sent inline
    /// (base64url-encoded JWK). Resource learns: a specific key signed this —
    /// identity unknown. Use for accountable access, rate-limiting by key.
    /// </summary>
    Hwk,
    /// <summary>
    /// <c>sig=jwks_uri</c> — Agent Identity mode. The resource fetches the
    /// agent's JWKS from a well-known URI to resolve the signing key.
    /// Resource learns: full agent identifier + verifiable public key.
    /// Use for access control by identity, replacing API keys.
    /// </summary>
    JwksUri,
    /// <summary>
    /// <c>sig=jkt-jwt</c> — Key Rotation mode. A naming JWT binds the current
    /// signing key to the agent's stable identity via JWK thumbprint confirmation.
    /// Supports key rotation without re-enrolment. Works with both Ed25519 and
    /// ECDSA P-256 keys.
    /// </summary>
    JktJwt,
}

/// <summary>
/// Configuration for the Guided Tour sample. Bound from the
/// <c>GuidedTour</c> section of <c>appsettings.json</c>.
/// </summary>
public sealed class TourOptions
{
    /// <summary>Base URL of the Aria <b>Profile</b> resource server (identity-based access).</summary>
    public string ProfileUrl { get; set; } = "http://localhost:5000";

    /// <summary>Base URL of the Aria <b>Inbox</b> resource server (resource-managed two-party AAuth-Access).</summary>
    public string InboxUrl { get; set; } = "http://localhost:5004";

    /// <summary>Base URL of the Aria <b>Calendar</b> resource server (PS-asserted three-party).</summary>
    public string CalendarUrl { get; set; } = "http://localhost:5001";

    /// <summary>Base URL of the Aria <b>Trips</b> resource server (mission-aware three-party).</summary>
    public string TripsUrl { get; set; } = "http://localhost:5002";

    /// <summary>Base URL of the Aria <b>Wallet</b> resource server (four-party federated).</summary>
    public string WalletUrl { get; set; } = "http://localhost:5003";

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
    /// Optional Concierge URL for the call-chain flow. When set, the
    /// call-chain tour targets this URL instead of the Calendar.
    /// </summary>
    public string? ConciergeUrl { get; set; }

    /// <summary>
    /// Optional Access Server URL for the four-party federated flow. When set,
    /// the Federated tour mode becomes selectable: the agent calls the
    /// Wallet's <c>/wallet</c> branch (whose resource token has
    /// <c>aud</c> = this AS), the Person Server federates to the AS, and the
    /// AS mints the <c>aa-auth+jwt</c> (<c>dwk=aauth-access.json</c>).
    /// </summary>
    public string? AccessServerUrl { get; set; }

    /// <summary>
    /// Which flow to walk by default when the page loads. Defaults to
    /// <see cref="TourMode.Bootstrap"/>; the user can flip to other
    /// modes via the in-page picker. When <see cref="PersonServerUrl"/>
    /// is empty, the tour forces <see cref="TourMode.Identity"/>
    /// regardless of this setting.
    /// </summary>
    public TourMode Mode { get; set; } = TourMode.Bootstrap;
}


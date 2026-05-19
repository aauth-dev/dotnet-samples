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
    Identity,
    Autonomous,
    Deferred,
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
    /// Which flow to walk by default when the page loads. Defaults to
    /// <see cref="TourMode.Autonomous"/>; the user can flip to
    /// <see cref="TourMode.Identity"/> or <see cref="TourMode.Deferred"/>
    /// via the in-page picker. When <see cref="PersonServerUrl"/> is
    /// empty, the tour forces <see cref="TourMode.Identity"/> regardless
    /// of this setting.
    /// </summary>
    public TourMode Mode { get; set; } = TourMode.Autonomous;
}


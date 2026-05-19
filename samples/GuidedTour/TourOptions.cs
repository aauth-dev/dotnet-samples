namespace GuidedTour;

/// <summary>
/// Which protocol flow the tour walks through. <see cref="Autonomous"/>
/// renders an 8-step "happy path" where the PS issues an auth token
/// immediately. <see cref="Deferred"/> renders the 11-step user-consent
/// path: exchange returns 202, the agent surfaces an interaction URL to
/// its user, the user approves, and the agent polls until the PS mints
/// the auth token.
/// </summary>
public enum TourMode
{
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
    /// it stops at step 4 (identity-based: signed GET returns 200).
    /// </summary>
    public string? PersonServerUrl { get; set; }

    /// <summary>Agent identifier embedded in the agent token's <c>sub</c>.</summary>
    public string AgentId { get; set; } = "aauth:tour-agent@ap.example";

    /// <summary>
    /// Which three-party flow to walk by default when the page loads.
    /// Defaults to <see cref="TourMode.Autonomous"/> (the simpler of the
    /// two flows); the user can flip to <see cref="TourMode.Deferred"/>
    /// via the in-page picker to see the user-consent path. Override in
    /// <c>appsettings.json</c> to change the initial selection.
    /// </summary>
    public TourMode Mode { get; set; } = TourMode.Autonomous;
}


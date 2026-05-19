namespace GuidedTour;

/// <summary>
/// Configuration for the Guided Tour sample. Bound from the
/// <c>GuidedTour</c> section of <c>appsettings.json</c>.
/// </summary>
public sealed class TourOptions
{
    /// <summary>Base URL of the WhoAmI resource server.</summary>
    public string WhoAmIUrl { get; set; } = "http://localhost:5000";

    /// <summary>
    /// Optional MockPersonServer URL. When set, the tour walks the full
    /// three-party autonomous flow; when null/empty it stops at step 4
    /// (identity-based: signed GET returns 200 directly).
    /// </summary>
    public string? PersonServerUrl { get; set; }

    /// <summary>Agent identifier embedded in the agent token's <c>sub</c>.</summary>
    public string AgentId { get; set; } = "aauth:tour-agent@ap.example";
}

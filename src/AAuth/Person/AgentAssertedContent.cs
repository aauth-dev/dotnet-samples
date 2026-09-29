namespace AAuth.Person;

/// <summary>
/// Content the agent asserted about its own request: the <c>justification</c>,
/// <c>platform</c> and <c>device</c> parameters of a person or auth token request
/// (§Consent Presentation). The agent chooses these words and gains from being
/// believed. A consent surface MUST attribute them to the agent and render them
/// visually distinct from resource-asserted content (the resource token claims in
/// <c>ResourceContext</c>), and MUST sanitize the Markdown <see cref="Justification"/>.
/// A PS MUST NOT base a decision solely on this content where resource-asserted
/// content covering the same operation is available.
/// </summary>
public sealed record AgentAssertedContent
{
    /// <summary>The agent's Markdown statement of why it needs access. Untrusted.</summary>
    public string? Justification { get; init; }

    /// <summary>The runtime platform the agent says it runs on. Untrusted.</summary>
    public string? Platform { get; init; }

    /// <summary>The device or browser the agent says it runs on. Untrusted.</summary>
    public string? Device { get; init; }
}

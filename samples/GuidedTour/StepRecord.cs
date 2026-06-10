namespace GuidedTour;

/// <summary>
/// One row in the Guided Tour timeline. Captures everything needed to
/// render the step in the UI without re-running it: titles, narrative,
/// the HTTP request/response and signature internals if applicable, and
/// decoded JWT payload(s) if the step minted or received a token.
/// </summary>
public sealed class StepRecord
{
    /// <summary>1-based step number.</summary>
    public required int Number { get; init; }

    /// <summary>One-line title shown in the step list.</summary>
    public required string Title { get; init; }

    /// <summary>Which actor performs this step in the sequence diagram.</summary>
    public required Actor From { get; init; }

    /// <summary>The recipient actor (same as <see cref="From"/> for local steps).</summary>
    public required Actor To { get; init; }

    /// <summary>Markdown-ish prose describing what's happening and why.</summary>
    public required string Narrative { get; init; }

    /// <summary>HTTP method + path for steps that send a request.</summary>
    public string? RequestLine { get; init; }

    /// <summary>Request headers, formatted one per line.</summary>
    public string? RequestHeaders { get; init; }

    /// <summary>Request body (typically JSON), or null.</summary>
    public string? RequestBody { get; init; }

    /// <summary>HTTP status line for steps that receive a response.</summary>
    public string? StatusLine { get; init; }

    /// <summary>Response headers, formatted one per line.</summary>
    public string? ResponseHeaders { get; init; }

    /// <summary>Response body (typically JSON).</summary>
    public string? ResponseBody { get; init; }

    /// <summary>The canonical RFC 9421 signature base, if the step signed a request.</summary>
    public string? SignatureBase { get; init; }

    /// <summary>A JWT minted or received during this step (compact form).</summary>
    public string? TokenJwt { get; init; }

    /// <summary>Decoded JWT header as pretty-printed JSON.</summary>
    public string? TokenHeader { get; init; }

    /// <summary>Decoded JWT payload as pretty-printed JSON.</summary>
    public string? TokenPayload { get; init; }

    /// <summary>Free-form decoded text for non-JWT artifacts (e.g. JWK thumbprint).</summary>
    public string? TokenDecoded { get; init; }

    /// <summary>C# SDK code snippet showing how to implement this step programmatically.</summary>
    public string? CodeSnippet { get; init; }

    /// <summary>
    /// Optional label naming which party actually runs the <see cref="CodeSnippet"/>
    /// (e.g. "the Agent Provider runs this"). Clarifies issuer-side code (minting
    /// tokens) versus client-side code an agent developer writes. Shown next to
    /// the "SDK code" disclosure summary when set.
    /// </summary>
    public string? CodeSnippetRole { get; init; }

    /// <summary>
    /// When true, the step's main sequence-diagram arrow is drawn as a dashed
    /// RETURN line (From → To) rather than a solid request line. Use for steps
    /// that model a response/return leg (e.g. a server handing a token back to
    /// a client) where <see cref="From"/> is the responder and <see cref="To"/>
    /// is the original caller.
    /// </summary>
    public bool IsResponse { get; init; }

    /// <summary>
    /// Optional sub-steps rendered as smaller arrows in the sequence diagram
    /// beneath this step's main arrow. Used to depict server-side actions
    /// (e.g. what the Concierge does internally on call-chaining).
    /// </summary>
    public IReadOnlyList<SubStep>? SubSteps { get; init; }

    /// <summary>
    /// Label shown on the sub-steps box, naming the component these inner
    /// steps run inside (e.g. "inside concierge", "inside person server").
    /// Defaults to "inside concierge" when not set.
    /// </summary>
    public string? SubStepsLabel { get; init; }

    /// <summary>Time the step was recorded (used for timeline display).</summary>
    public DateTimeOffset Timestamp { get; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// A lightweight visual-only arrow in the sequence diagram, rendered as
/// part of a parent step. Does not appear in the step list or inspector.
/// Set <paramref name="IsResponse"/> to draw the arrow as a dashed return
/// (response) line rather than a solid outgoing request.
/// </summary>
public sealed record SubStep(string Label, Actor From, Actor To, bool IsResponse = false);

/// <summary>Actors in the AAuth protocol flow as visualized by the tour.</summary>
public enum Actor
{
    Agent,
    Resource,
    PersonServer,
    AgentProvider,
    Concierge,
    AccessServer,
    Parent,
    SubAgent,
}

/// <summary>
/// Static description of a planned tour step. Used by the step list to
/// render upcoming steps with titles + one-line descriptions before
/// they've been recorded. Once a step runs its <see cref="StepRecord"/>
/// supersedes the plan entry in the UI.
/// </summary>
public sealed record TourPlanStep(
    int Number,
    string Title,
    string Description,
    Actor From,
    Actor To);

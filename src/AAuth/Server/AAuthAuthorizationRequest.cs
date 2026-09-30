using AAuth.Server.Verification;

namespace AAuth.Server;

/// <summary>
/// The verified inputs of a signed <c>POST authorization_endpoint</c> request
/// (§Authorization Endpoint Request), passed to the handler registered via
/// <c>MapAAuthAuthorizationEndpoint</c>. The person token identity and key are
/// in <see cref="Verification"/>. <see cref="Scope"/> is the requested
/// space-separated scope string from the request body, unless a companion
/// extension such as R3 supplies the authorization claim instead.
/// </summary>
/// <param name="Scope">The requested scope (space-separated), from the request body's <c>scope</c> field.</param>
/// <param name="Verification">The verified AAuth person-token result for the signed request.</param>
public sealed record AAuthAuthorizationRequest(string? Scope, AAuthVerificationResult Verification)
{
	public string? Account { get; init; }

    /// <summary>Companion extension state parsed from the request body.</summary>
    public IDictionary<string, object?> Features { get; } = new Dictionary<string, object?>(StringComparer.Ordinal);
}

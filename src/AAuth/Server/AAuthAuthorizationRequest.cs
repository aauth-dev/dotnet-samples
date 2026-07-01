using AAuth.Server.Verification;

namespace AAuth.Server;

/// <summary>
/// The verified inputs of a signed <c>POST authorization_endpoint</c> request
/// (§Authorization Endpoint Request), passed to the handler registered via
/// <c>MapAAuthAuthorizationEndpoint</c>. The agent's identity and key are in
/// <see cref="Verification"/>; <see cref="Scope"/> is the requested
/// space-separated scope string from the request body.
/// </summary>
/// <param name="Scope">The requested scope (space-separated), from the request body's <c>scope</c> field.</param>
/// <param name="Verification">The verified AAuth result for the signed request (agent identity, key thumbprint, etc.).</param>
public sealed record AAuthAuthorizationRequest(string Scope, AAuthVerificationResult Verification);

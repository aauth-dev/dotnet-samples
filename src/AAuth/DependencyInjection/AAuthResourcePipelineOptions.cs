using System.Collections.Generic;
using AAuth.Server;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;

namespace AAuth;

/// <summary>
/// Options for the unified <see cref="AAuthApplicationBuilderExtensions.MapAAuthResource"/>
/// pipeline, controlling verification and challenge behavior.
/// </summary>
public sealed class AAuthResourcePipelineOptions
{
    public Func<Microsoft.AspNetCore.Http.HttpContext, string?>? AccountSelector { get; set; }
    /// <summary>
    /// Access mode controlling whether the middleware challenges or passes through.
    /// Default: <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public AAuthAccessMode AccessMode { get; set; } = AAuthAccessMode.RequireAuthToken;

    /// <summary>Trust for auth-token, person-token and agent-token issuers. Open by default.</summary>
    public AAuth.Server.AAuthTrustOptions Trust { get; set; } = new();

    /// <summary>
    /// Default scopes to request in the resource token. Space-separated.
    /// </summary>
    public string? DefaultScopes { get; set; }
}

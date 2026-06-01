using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AAuth.Server;

/// <summary>
/// ASP.NET Core authentication handler that maps <see cref="AAuthVerificationResult"/>
/// (stored in <c>HttpContext.Features</c>) to a <see cref="ClaimsPrincipal"/>.
/// </summary>
/// <remarks>
/// This handler does NOT perform verification itself — it reads the result
/// produced by the upstream <see cref="AAuthVerificationMiddleware"/>. Register using
/// <c>services.AddAAuthAuthentication()</c>.
/// </remarks>
public sealed class AAuthAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    /// <summary>The authentication scheme name.</summary>
    public const string SchemeName = "AAuth";

    /// <summary>Claim type for the AAuth level.</summary>
    public const string LevelClaimType = "aauth:level";

    /// <summary>Claim type for the signature-key scheme.</summary>
    public const string SchemeClaimType = "aauth:scheme";

    /// <summary>Claim type for the agent identifier.</summary>
    public const string AgentClaimType = "aauth:agent";

    /// <summary>Claim type for the JWK thumbprint.</summary>
    public const string JktClaimType = "aauth:jkt";

    /// <summary>Claim type for the issuer.</summary>
    public const string IssuerClaimType = "aauth:issuer";

    /// <summary>Claim type for individual scopes.</summary>
    public const string ScopeClaimType = "aauth:scope";

    /// <summary>Claim type for individual groups (one claim per group).</summary>
    public const string GroupClaimType = "aauth:group";

    /// <summary>Claim type for the actor subject.</summary>
    public const string ActorSubjectClaimType = "aauth:act_sub";

    /// <summary>Create the handler.</summary>
    public AAuthAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    /// <inheritdoc/>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = Context.Features.Get<AAuthVerificationResult>();
        if (result is null)
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = new List<Claim>
        {
            new(LevelClaimType, result.Level.ToString()),
            new(SchemeClaimType, result.Scheme),
        };

        if (result.Subject is not null)
        {
            claims.Add(new Claim(ClaimTypes.NameIdentifier, result.Subject));
        }

        if (result.Agent is not null)
        {
            claims.Add(new Claim(AgentClaimType, result.Agent));
        }

        if (result.Jkt is not null)
        {
            claims.Add(new Claim(JktClaimType, result.Jkt));
        }

        if (result.Issuer is not null)
        {
            claims.Add(new Claim(IssuerClaimType, result.Issuer));
        }

        if (result.ActorSubject is not null)
        {
            claims.Add(new Claim(ActorSubjectClaimType, result.ActorSubject));
        }

        foreach (var scope in result.Scopes)
        {
            claims.Add(new Claim(ScopeClaimType, scope));
        }

        // Map enterprise roles to the standard ASP.NET role claim so
        // [Authorize(Roles=...)] / RequireRole() work out of the box.
        foreach (var role in result.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        foreach (var group in result.Groups)
        {
            claims.Add(new Claim(GroupClaimType, group));
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

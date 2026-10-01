using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Person;

/// <summary>Explicit PS-AS collapse declaration for one resource and local AS role instance.</summary>
public sealed class AAuthCollapsedFederationDeclaration
{
    /// <summary>The verified resource issuer that chose the collocated AS.</summary>
    public required string ResourceIssuer { get; init; }

    /// <summary>The linked local Access Server role instance name.</summary>
    public string AccessServerName { get; init; } = Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder.DefaultName;

    /// <summary>The issuer the linked AS role must use.</summary>
    public required string ExpectedAccessServerIssuer { get; init; }
}

/// <summary>Context used to decide whether a verified request declares PS-AS collapse.</summary>
public sealed class AAuthCollapsedFederationContext
{
    /// <summary>Request services.</summary>
    public required System.IServiceProvider Services { get; init; }

    /// <summary>The current HTTP request.</summary>
    public required HttpContext HttpContext { get; init; }

    /// <summary>The Person Server role instance name.</summary>
    public required string PersonServerName { get; init; }

    /// <summary>The Person Server issuer.</summary>
    public required string PersonServerIssuer { get; init; }

    /// <summary>The verified resource issuer.</summary>
    public required string ResourceIssuer { get; init; }

    /// <summary>The verified resource-token payload.</summary>
    public required JsonObject ResourceTokenPayload { get; init; }

    /// <summary>The requested scope.</summary>
    public required string Scope { get; init; }

    /// <summary>The requested account, if any.</summary>
    public string? Account { get; init; }

    /// <summary>The verified presented-token identity.</summary>
    public required TokenVerifier.VerifiedToken PresentedToken { get; init; }
}

/// <summary>Decision from <see cref="IAAuthCollapsedFederationPolicy"/>.</summary>
public sealed class AAuthCollapsedFederationDecision
{
    private AAuthCollapsedFederationDecision(bool declared, string? accessServerName, string? expectedAccessServerIssuer)
    {
        Declared = declared;
        AccessServerName = accessServerName;
        ExpectedAccessServerIssuer = expectedAccessServerIssuer;
    }

    /// <summary>True when the resource explicitly declared a collocated AS.</summary>
    public bool Declared { get; }

    /// <summary>The linked local AS role instance name.</summary>
    public string? AccessServerName { get; }

    /// <summary>The expected AS issuer.</summary>
    public string? ExpectedAccessServerIssuer { get; }

    /// <summary>No collapse declaration matched.</summary>
    public static AAuthCollapsedFederationDecision NotDeclared { get; } = new(false, null, null);

    /// <summary>Declare collapse for a linked AS role instance.</summary>
    public static AAuthCollapsedFederationDecision Declare(string accessServerName, string expectedAccessServerIssuer)
        => new(true, accessServerName, expectedAccessServerIssuer);
}

/// <summary>Policy seam that recognizes explicit PS-AS collapse declarations.</summary>
public interface IAAuthCollapsedFederationPolicy
{
    /// <summary>Evaluate the verified request.</summary>
    ValueTask<AAuthCollapsedFederationDecision> EvaluateAsync(
        AAuthCollapsedFederationContext context,
        CancellationToken cancellationToken = default);
}

internal sealed class ConfiguredCollapsedFederationPolicy(
    IReadOnlyList<AAuthCollapsedFederationDeclaration> declarations) : IAAuthCollapsedFederationPolicy
{
    public ValueTask<AAuthCollapsedFederationDecision> EvaluateAsync(
        AAuthCollapsedFederationContext context,
        CancellationToken cancellationToken = default)
    {
        var match = declarations.FirstOrDefault(declaration =>
            string.Equals(declaration.ResourceIssuer, context.ResourceIssuer, System.StringComparison.Ordinal));
        return ValueTask.FromResult(match is null
            ? AAuthCollapsedFederationDecision.NotDeclared
            : AAuthCollapsedFederationDecision.Declare(match.AccessServerName, match.ExpectedAccessServerIssuer));
    }
}

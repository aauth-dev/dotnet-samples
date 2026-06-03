using System;
using System.Collections.Generic;
using AAuth;

namespace AAuth.Headers;

/// <summary>
/// Typed projection of an <c>AAuth-Requirement: requirement=interaction</c>
/// header (AAuth protocol §User Interaction). Carries the user-facing
/// interaction <c>url</c> and the single-use <c>code</c> the agent must
/// hand to its user. See
/// <see href="https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/">draft-hardt-oauth-aauth-protocol §User Interaction</see>.
/// </summary>
/// <remarks>
/// <para>This sits beside <see cref="AAuthRequirementHeader"/>; that
/// parser handles all requirement types as a dictionary, this type only
/// projects the <c>interaction</c>-specific shape so callers don't have
/// to fish the parameters out by string key.</para>
/// </remarks>
public sealed record Interaction(string Url, string Code)
{
    /// <summary>Requirement type: <c>interaction</c>.</summary>
    public const string RequirementType = "interaction";

    /// <summary>The parameter name carrying the interaction endpoint URL.</summary>
    public const string UrlParameter = "url";

    /// <summary>The parameter name carrying the single-use interaction code.</summary>
    public const string CodeParameter = "code";

    /// <summary>
    /// Build the user-facing interaction URL the agent shows to its user
    /// (browser redirect, QR code, or display code). The agent MAY append
    /// a <paramref name="callback"/> query parameter when it has a
    /// browser; if omitted, the server displays a completion page and the
    /// agent relies on polling.
    /// </summary>
    public string BuildUserUrl(string? callback = null)
    {
        var separator = Url.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        var baseUrl = $"{Url}{separator}code={Uri.EscapeDataString(Code)}";
        return callback is null
            ? baseUrl
            : $"{baseUrl}&callback={Uri.EscapeDataString(callback)}";
    }

    /// <summary>
    /// Project an <c>interaction</c> requirement out of a parsed
    /// <c>AAuth-Requirement</c> header. Returns <see langword="null"/>
    /// when the requirement is something else (e.g. <c>auth-token</c>).
    /// Throws <see cref="FormatException"/> when the requirement is
    /// <c>interaction</c> but is missing the mandatory <c>url</c> or
    /// <c>code</c> parameters.
    /// </summary>
    public static Interaction? FromRequirement(AAuthRequirementHeader.ParsedRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(requirement);
        if (requirement.Requirement != RequirementType)
        {
            return null;
        }

        if (!requirement.Parameters.TryGetValue(UrlParameter, out var url)
            || string.IsNullOrEmpty(url))
        {
            throw new FormatException(
                $"AAuth-Requirement requirement=interaction is missing the '{UrlParameter}' parameter.");
        }
        if (!AAuthUrl.IsHttpsOrLoopback(url))
        {
            // Reject non-http(s) schemes (e.g. `javascript:`, `data:`) so a
            // hostile or buggy PS cannot smuggle a script URL into the agent
            // host, which may render it as a clickable link.
            throw new FormatException(
                $"AAuth-Requirement requirement=interaction '{UrlParameter}' must be an absolute https URL (loopback http allowed for development).");
        }
        if (!requirement.Parameters.TryGetValue(CodeParameter, out var code)
            || string.IsNullOrEmpty(code))
        {
            throw new FormatException(
                $"AAuth-Requirement requirement=interaction is missing the '{CodeParameter}' parameter.");
        }

        return new Interaction(url, code);
    }

    /// <summary>
    /// Format an <c>interaction</c> requirement header value. Mirrors
    /// <see cref="AAuthRequirementHeader.FormatAuthToken"/>'s shape so
    /// resource and PS implementations can emit the header without a
    /// general RFC 8941 serializer.
    /// </summary>
    public static string Format(string url, string code)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);
        ArgumentException.ThrowIfNullOrEmpty(code);
        if (!AAuthUrl.IsHttpsOrLoopback(url))
        {
            throw new ArgumentException(
                "url must be an absolute https URL (loopback http allowed for development).",
                nameof(url));
        }
        Reject(url, nameof(url));
        Reject(code, nameof(code));
        return $"requirement={RequirementType}; {UrlParameter}=\"{url}\"; {CodeParameter}=\"{code}\"";

        static void Reject(string value, string name)
        {
            foreach (var c in value)
            {
                if (c < 0x20 || c == 0x7F || c == '"' || c == '\\')
                {
                    throw new ArgumentException(
                        $"{name} must not contain control characters, quotes, or backslashes.",
                        name);
                }
            }
        }
    }
}

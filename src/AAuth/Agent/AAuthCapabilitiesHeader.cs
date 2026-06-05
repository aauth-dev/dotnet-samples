using System;
using System.Collections.Generic;
using System.Linq;

namespace AAuth.Agent;

/// <summary>
/// Models the <c>AAuth-Capabilities</c> header that agents send on outbound
/// requests to declare what flows they support (§14.1).
/// </summary>
public static class AAuthCapabilitiesHeader
{
    /// <summary>The HTTP header name.</summary>
    public const string Name = "AAuth-Capabilities";

    /// <summary>Known capability values.</summary>
    public static class Capabilities
    {
        /// <summary>Agent can handle interaction flows (redirect to URL + code).</summary>
        public const string Interaction = "interaction";

        /// <summary>Agent can handle clarification requirements.</summary>
        public const string Clarification = "clarification";

        /// <summary>Agent can handle payment-required flows (402).</summary>
        public const string Payment = "payment";

        /// <summary>Agent can handle mission flows.</summary>
        public const string Mission = "mission";
    }

    /// <summary>Format the header value from a set of capabilities.</summary>
    public static string Format(IEnumerable<string> capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        return string.Join(", ", capabilities);
    }

    /// <summary>Format the header value from individual capabilities.</summary>
    public static string Format(params string[] capabilities) => Format((IEnumerable<string>)capabilities);

    /// <summary>Parse a capabilities header value into individual capability tokens.</summary>
    public static IReadOnlyList<string> Parse(string headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            return Array.Empty<string>();
        return headerValue.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// Union the mission-provided capabilities with the agent's own capabilities,
    /// preserving order (mission first, then agent) and removing duplicates
    /// case-sensitively. Per §Mission Approval, the agent unions the capabilities
    /// the PS can provide for the session with its own when constructing the
    /// <c>AAuth-Capabilities</c> request header.
    /// </summary>
    public static IReadOnlyList<string> Union(
        IEnumerable<string>? missionCapabilities,
        IEnumerable<string>? agentCapabilities)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<string>();

        void Add(IEnumerable<string>? source)
        {
            if (source is null)
                return;
            foreach (var capability in source)
            {
                if (string.IsNullOrWhiteSpace(capability))
                    continue;
                var trimmed = capability.Trim();
                if (seen.Add(trimmed))
                    result.Add(trimmed);
            }
        }

        Add(missionCapabilities);
        Add(agentCapabilities);
        return result;
    }
}

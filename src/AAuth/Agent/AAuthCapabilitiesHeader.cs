using System;
using System.Collections.Generic;
using System.Linq;
using AAuth.Protocol;

namespace AAuth.Agent;

/// <summary>
/// Models the <c>AAuth-Capabilities</c> header that agents send on outbound
/// requests to declare what flows they support (§AAuth-Capabilities Request
/// Header).
/// </summary>
public static class AAuthCapabilitiesHeader
{
    /// <summary>The HTTP header name.</summary>
    public const string Name = AAuthConstants.Headers.AAuthCapabilities;

    /// <summary>Format the header value from a set of capabilities.</summary>
    public static string Format(IEnumerable<string> capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        return string.Join(", ", AAuthProtocolInput.ValidateCapabilities(capabilities, nameof(capabilities)));
    }

    /// <summary>Format the header value from individual capabilities.</summary>
    public static string Format(params string[] capabilities) => Format((IEnumerable<string>)capabilities);

    /// <summary>Parse a capabilities header value into individual capability tokens.</summary>
    public static IReadOnlyList<string> Parse(string headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            return Array.Empty<string>();
        var result = new List<string>();
        foreach (var rawItem in headerValue.Split(','))
        {
            var item = rawItem.Trim();
            if (item.Length == 0)
            {
                throw new FormatException("AAuth-Capabilities must be a Structured Field List of Tokens.");
            }

            var tokenEnd = item.IndexOf(';');
            var token = tokenEnd < 0 ? item : item[..tokenEnd].TrimEnd();
            if (!AAuthProtocolInput.IsStructuredFieldToken(token))
            {
                throw new FormatException("AAuth-Capabilities item is not a Structured Field Token.");
            }

            if (tokenEnd >= 0)
            {
                ValidateParameters(item[(tokenEnd + 1)..]);
            }

            result.Add(token);
        }

        return AAuthProtocolInput.ValidateCapabilities(result, nameof(headerValue));
    }

    private static void ValidateParameters(string parameters)
    {
        foreach (var rawParameter in parameters.Split(';'))
        {
            var parameter = rawParameter.Trim();
            if (parameter.Length == 0)
            {
                throw new FormatException("AAuth-Capabilities contains an empty item parameter.");
            }

            var equals = parameter.IndexOf('=');
            var name = equals < 0 ? parameter : parameter[..equals].TrimEnd();
            if (!AAuthProtocolInput.IsStructuredFieldToken(name))
            {
                throw new FormatException("AAuth-Capabilities contains an invalid item parameter.");
            }

            if (equals >= 0 && parameter[(equals + 1)..].Trim().Length == 0)
            {
                throw new FormatException("AAuth-Capabilities contains an empty parameter value.");
            }
        }
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
                var trimmed = AAuthProtocolInput.ValidateCapability(capability, nameof(capability));
                if (seen.Add(trimmed))
                    result.Add(trimmed);
            }
        }

        Add(missionCapabilities);
        Add(agentCapabilities);
        return result;
    }
}

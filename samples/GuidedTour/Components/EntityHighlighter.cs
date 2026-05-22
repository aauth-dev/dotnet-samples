using System.Text.RegularExpressions;

namespace GuidedTour.Components;

/// <summary>
/// Highlights known agent, resource, and person-server URLs/IDs in
/// already-HTML-escaped text by wrapping matches in colored spans with
/// a tooltip indicating what entity the value represents.
/// </summary>
public sealed class EntityHighlighter
{
    private readonly (string Pattern, string CssClass, string Label)[] _rules;

    public EntityHighlighter(TourOptions options)
    {
        // Build patterns from longest to shortest so longer matches win.
        // Use the base origin (scheme+host+port) for URLs so any path
        // under that origin gets highlighted.
        var entries = new List<(string Value, string CssClass, string Label)>();

        // Agent identifiers
        if (!string.IsNullOrWhiteSpace(options.AgentId))
            entries.Add((options.AgentId, "hl-agent", "Agent"));
        if (!string.IsNullOrWhiteSpace(options.AgentProviderUrl))
            entries.Add((BaseOrigin(options.AgentProviderUrl), "hl-agent", "Agent Provider"));

        // Resource
        if (!string.IsNullOrWhiteSpace(options.WhoAmIUrl))
            entries.Add((BaseOrigin(options.WhoAmIUrl), "hl-resource", "Resource"));

        // Person Server
        if (!string.IsNullOrWhiteSpace(options.PersonServerUrl))
            entries.Add((BaseOrigin(options.PersonServerUrl), "hl-ps", "Person Server"));

        _rules = entries
            .OrderByDescending(e => e.Value.Length)
            .Select(e => (Regex.Escape(System.Net.WebUtility.HtmlEncode(e.Value)), e.CssClass, e.Label))
            .ToArray();
    }

    private static string BaseOrigin(string url)
        => new Uri(url).GetLeftPart(UriPartial.Authority);

    /// <summary>
    /// Wraps occurrences of known entity values in the given HTML-escaped
    /// text with <c>&lt;span class="hl-*" title="..."&gt;</c> elements.
    /// For URL origins, the match extends to include any trailing path/query
    /// characters so the full URL is colored.
    /// </summary>
    public string Highlight(string escapedHtml)
    {
        foreach (var (pattern, cssClass, label) in _rules)
        {
            // Extend the match to grab any trailing URL path characters
            // (letters, digits, /, -, _, ., ~, %, :, @, !, $, &, ', (, ), *, +, ,, ;, =, ?)
            escapedHtml = Regex.Replace(
                escapedHtml,
                pattern + @"[A-Za-z0-9/\-._~%:@!$&'()*+,;=?]*",
                $"<span class=\"{cssClass}\" title=\"{label}\">$0</span>");
        }
        return escapedHtml;
    }

    /// <summary>
    /// Tests whether the given HTML-escaped string value (without surrounding
    /// quotes) matches a known entity. Returns the CSS class and label if so.
    /// </summary>
    public (string CssClass, string Label)? Classify(string escapedValue)
    {
        foreach (var (pattern, cssClass, label) in _rules)
        {
            if (Regex.IsMatch(escapedValue, "^" + pattern + @"[A-Za-z0-9/\-._~%:@!$&'()*+,;=?]*$"))
                return (cssClass, label);
        }
        return null;
    }
}

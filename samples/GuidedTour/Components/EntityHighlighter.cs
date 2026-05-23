using System.Text;
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

    private const string ExtLinkIcon =
        "<a class=\"ext-link\" href=\"{0}\" target=\"_blank\" rel=\"noopener\" title=\"Open in new tab\">"
        + "<svg width=\"12\" height=\"12\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\">"
        + "<path d=\"M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3\"/>"
        + "</svg></a>";

    /// <summary>
    /// Wraps occurrences of known entity values in the given HTML-escaped
    /// text with <c>&lt;span class="hl-*" title="..."&gt;</c> elements.
    /// Uses single-pass matching to prevent nested/overlapping spans.
    /// Appends a small open-in-new-tab icon after URL matches.
    /// </summary>
    public string Highlight(string escapedHtml)
    {
        // Collect all matches from all rules in one pass.
        var matches = new List<(int Start, int Length, string CssClass, string Label)>();

        foreach (var (pattern, cssClass, label) in _rules)
        {
            // Extend the match to grab trailing URL path characters.
            // Excludes & so we don't bleed into HTML entities (&quot; etc.).
            foreach (Match m in Regex.Matches(
                escapedHtml,
                pattern + @"[A-Za-z0-9/\-._~%:@!$'()*+,;=?]*"))
            {
                matches.Add((m.Index, m.Length, cssClass, label));
            }
        }

        // Sort by start position; for overlaps, longest match wins.
        matches.Sort((a, b) => a.Start != b.Start
            ? a.Start.CompareTo(b.Start)
            : b.Length.CompareTo(a.Length));

        // Remove overlapping matches — keep the first (longest) at each position.
        var filtered = new List<(int Start, int Length, string CssClass, string Label)>();
        int lastEnd = 0;
        foreach (var m in matches)
        {
            if (m.Start >= lastEnd)
            {
                filtered.Add(m);
                lastEnd = m.Start + m.Length;
            }
        }

        // Apply from end to start so indices stay valid.
        var sb = new StringBuilder(escapedHtml);
        for (int i = filtered.Count - 1; i >= 0; i--)
        {
            var (start, length, cssClass, label) = filtered[i];
            var matchText = sb.ToString(start, length);

            // If the URL is followed by &quot; (closing JSON quote), consume
            // it so the icon lands outside the quote.
            var afterEnd = start + length;
            var trailingQuote = "";
            if (afterEnd + 6 <= sb.Length && sb.ToString(afterEnd, 6) == "&quot;")
            {
                trailingQuote = "&quot;";
                sb.Remove(afterEnd, 6);
            }

            sb.Remove(start, length);

            var icon = matchText.StartsWith("http")
                ? string.Format(ExtLinkIcon, matchText)
                : "";
            sb.Insert(start, $"<span class=\"{cssClass}\" title=\"{label}\">{matchText}</span>{trailingQuote}{icon}");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Tests whether the given HTML-escaped string value (without surrounding
    /// quotes) matches a known entity. Returns the CSS class and label if so.
    /// </summary>
    public (string CssClass, string Label)? Classify(string escapedValue)
    {
        foreach (var (pattern, cssClass, label) in _rules)
        {
            if (Regex.IsMatch(escapedValue, "^" + pattern + @"[A-Za-z0-9/\-._~%:@!$'()*+,;=?]*$"))
                return (cssClass, label);
        }
        return null;
    }
}

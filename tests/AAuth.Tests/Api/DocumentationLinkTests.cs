using System.Text.RegularExpressions;
using Xunit;

namespace AAuth.Tests.Api;

public sealed class DocumentationLinkTests
{
    [Fact]
    public void ActiveMarkdown_LocalLinksAndAnchorsResolve()
    {
        var root = DocumentationInventory.Root;
        var files = DocumentationInventory.Files().Where(file => file.EndsWith(".md"))
            .Concat(new[] { "aauth-spec/SPEC-VERSION.md", "aauth-spec/CHANGELOG.md" })
            .Concat(new[] { "implementation-plan.md", "implementation-log.md", "capability-scenarios.md", "conformance-ledger.md", "api-surface-map.md", "docs-surface-map.md" }
                .Select(file => ".agent/plans/2026-09-08-aauth-v10-spec-migration/" + file)).ToArray();
        var failures = new List<string>();
        var checkedLinks = 0;
        foreach (var file in files)
        {
            var source = File.ReadAllText(Path.Combine(root, file));
            source = Regex.Replace(source, @"(?m)^[ \t]*```[^\r\n]*\r?\n[\s\S]*?^[ \t]*```[ \t]*\r?$", "");
            foreach (Match match in Regex.Matches(source, @"\[[^\]\r\n]*\]\((?<url>[^\s)]+)(?:\s+""[^""]*"")?\)"))
            {
                var url = match.Groups["url"].Value.Trim('<', '>');
                if (Regex.IsMatch(url, @"^[a-zA-Z][a-zA-Z0-9+.-]*:") || url.StartsWith("//")) continue;
                var parts = url.Split('#', 2);
                var path = Path.GetFullPath(Path.Combine(root, Path.GetDirectoryName(file)!, Uri.UnescapeDataString(parts[0])));
                if (parts[0].Length == 0) path = Path.Combine(root, file);
                checkedLinks++;
                if (!File.Exists(path) && !Directory.Exists(path)) { failures.Add($"{file}: missing {url}"); continue; }
                if (parts.Length == 1 || parts[1].Length == 0 || Directory.Exists(path)) continue;
                var fragment = Uri.UnescapeDataString(parts[1]);
                var target = File.ReadAllText(path);
                if (Regex.IsMatch(fragment, @"^L\d+(?:-L\d+)?$"))
                {
                    var numbers = Regex.Matches(fragment, @"\d+").Select(number => int.Parse(number.Value));
                    if (numbers.Any(number => number < 1 || number > target.Count(character => character == '\n') + 1)) failures.Add($"{file}: out-of-range {url}");
                    continue;
                }
                if (!path.EndsWith(".md")) continue;
                var anchors = Anchors(target);
                if (!anchors.Contains(fragment)) failures.Add($"{file}: missing anchor {url}");
            }
        }
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "aauth-phase13-links.txt"), $"{files.Length} Markdown files; {checkedLinks} local links\n" + string.Join("\n", failures));
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    private static HashSet<string> Anchors(string source)
    {
        var anchors = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match match in Regex.Matches(source, @"\{#(?<id>[^} ]+)\}|\bid=[""'](?<id>[^""']+)[""']")) anchors.Add(match.Groups["id"].Value);
        source = Regex.Replace(source, @"(?m)^[ \t]*```[^\r\n]*\r?\n[\s\S]*?^[ \t]*```[ \t]*\r?$", "");
        foreach (Match match in Regex.Matches(source, @"(?m)^#{1,6} +(?<heading>.+?)\s*$"))
        {
            var heading = Regex.Replace(match.Groups["heading"].Value, @"\s*\{#[^}]+\}", "").TrimEnd('#').Trim();
            heading = Regex.Replace(heading, @"\[([^\]]+)\]\([^)]+\)", "$1");
            var slug = Regex.Replace(heading.ToLowerInvariant(), @"[^\p{L}\p{Nd}_\-\s]", "").Replace(' ', '-');
            var candidate = slug;
            var suffix = 0;
            while (!anchors.Add(candidate)) candidate = $"{slug}-{++suffix}";
        }
        return anchors;
    }
}
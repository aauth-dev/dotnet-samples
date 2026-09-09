using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace AAuth.Tests.Api;

internal sealed record DocumentationSnippet(string File, string Id, int Line, string Language, string Code)
{
    public string Key => $"{File}:{Id}";
    public string Hash => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Code)));
}

internal static class DocumentationInventory
{
    internal static string Root
    {
        get
        {
            for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
                if (File.Exists(Path.Combine(directory.FullName, "AAuth.slnx"))) return directory.FullName;
            throw new InvalidOperationException("Repository root was not found.");
        }
    }

    internal static IEnumerable<string> Files()
    {
        yield return "README.md";
        foreach (var directory in new[] { "docs", "src", "samples" })
            foreach (var file in Directory.EnumerateFiles(Path.Combine(Root, directory), "*", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(Root, file).Replace('\\', '/');
                if (relative.Split('/').Any(part => part is "bin" or "obj" or "node_modules" or "test-results" or "playwright-report")) continue;
                if (relative.EndsWith(".md", StringComparison.Ordinal)
                    || new[] { "samples/GuidedTour/", "samples/SampleApp/", "samples/CapabilitySupport/", "samples/EventSupport/" }
                        .Any(relative.StartsWith) && (relative.EndsWith(".cs") || relative.EndsWith(".razor") || relative.EndsWith(".ts")))
                    yield return relative;
            }
    }

    internal static IReadOnlyList<DocumentationSnippet> Read()
    {
        var snippets = new List<DocumentationSnippet>();
        foreach (var file in Files().Order())
        {
            var source = File.ReadAllText(Path.Combine(Root, file));
            int Line(int offset) => source.AsSpan(0, offset).Count('\n') + 1;
            if (file.EndsWith(".md"))
            {
                var markdown = Regex.Replace(source, @"(?m)^(?:> ?)+", "");
                var index = 0;
                foreach (Match match in Regex.Matches(markdown, @"(?m)^[ \t]*```(?<language>[^\r\n`]*)\r?\n(?<code>[\s\S]*?)^[ \t]*```[ \t]*\r?$"))
                    snippets.Add(new(file, $"fence-{++index}", markdown.AsSpan(0, match.Index).Count('\n') + 1, match.Groups["language"].Value.Trim(), match.Groups["code"].Value));
                continue;
            }
            if (file.EndsWith(".ts")) continue;
            if (file.EndsWith(".razor"))
            {
                var index = 0;
                var blocks = Regex.Matches(source, @"<pre\b[^>]*>(?<code>[\s\S]*?)</pre>");
                foreach (Match match in blocks)
                {
                    var body = match.Groups["code"].Value;
                    var language = Regex.Match(body, "language-([a-zA-Z0-9]+)").Groups[1].Value;
                    body = Regex.Replace(body, "</?code[^>]*>", "");
                    snippets.Add(new(file, $"pre-{++index}", Line(match.Index), body.TrimStart().StartsWith('@') ? "dynamic" : language, WebUtility.HtmlDecode(body)));
                }
                index = 0;
                foreach (Match match in Regex.Matches(source, @"<code\b[^>]*>(?<code>[\s\S]*?)</code>"))
                    if (!blocks.Any(block => match.Index >= block.Index && match.Index < block.Index + block.Length))
                        snippets.Add(new(file, $"inline-{++index}", Line(match.Index), "inline-code", WebUtility.HtmlDecode(match.Groups["code"].Value)));
            }
            var syntax = CSharpSyntaxTree.ParseText(source).GetRoot();
            var strings = syntax.DescendantNodes().OfType<ExpressionSyntax>()
                .Where(expression => expression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression)
                    || expression is InterpolatedStringExpressionSyntax)
                .Where(expression => expression.ToString().Contains('\n')
                    || expression.Parent is AssignmentExpressionSyntax assignment
                        && assignment.Left.ToString() is "snippet" or "CodeSnippet");
            var number = 0;
            foreach (var expression in strings)
            {
                var name = expression.Ancestors().OfType<VariableDeclaratorSyntax>().FirstOrDefault()?.Identifier.Text
                    ?? expression.Ancestors().OfType<PropertyDeclarationSyntax>().FirstOrDefault()?.Identifier.Text
                    ?? expression.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "string";
                var code = expression is LiteralExpressionSyntax literal ? literal.Token.ValueText : expression.ToString();
                var language = expression is InterpolatedStringExpressionSyntax ? "interpolated"
                    : file.EndsWith("CodeSnippets.cs") || file.EndsWith("WalletScenarioCode.cs")
                        || file.EndsWith("EventDemoCode.cs") || name.EndsWith("Example", StringComparison.Ordinal)
                        || name.Contains("Code") || name.Contains("Snippet") || name is "Example"
                        || expression.Parent is AssignmentExpressionSyntax assignment && assignment.Left.ToString() is "snippet" or "CodeSnippet"
                        ? "csharp" : "string";
                snippets.Add(new(file, $"{name}-{++number}", Line(expression.SpanStart), language, code));
            }
        }
        return snippets;
    }
}
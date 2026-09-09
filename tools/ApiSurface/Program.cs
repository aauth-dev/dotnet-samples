using System.Diagnostics;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

var root = Path.GetFullPath(args.ElementAtOrDefault(0) ?? ".");
var baseline = args.ElementAtOrDefault(1) ?? "ba768f1";
var mapPath = Path.Combine(root, ".agent/plans/2026-09-08-aauth-v10-spec-migration/api-surface-map.md");
const string marker = "<!-- generated-public-api-delta -->";
var baselineFiles = Git("ls-tree", "-r", "--name-only", baseline, "--", "src", "samples")
    .Split('\n', StringSplitOptions.RemoveEmptyEntries).Where(IsSource).ToHashSet(StringComparer.Ordinal);
var currentFiles = new[] { "src", "samples" }.SelectMany(folder => Directory.EnumerateFiles(Path.Combine(root, folder), "*.cs", SearchOption.AllDirectories))
    .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/')).Where(IsSource).ToHashSet(StringComparer.Ordinal);
var output = new StringBuilder();
var entries = new List<(string Path, List<ApiEntry> Old, List<ApiEntry> Current)>();
foreach (var path in baselineFiles.Union(currentFiles).Order(StringComparer.Ordinal))
{
    var oldSource = baselineFiles.Contains(path) ? Git("show", $"{baseline}:{path}") : "";
    var newSource = currentFiles.Contains(path) ? File.ReadAllText(Path.Combine(root, path)) : "";
    if (oldSource == newSource) continue;
    var oldApi = ReadApi(oldSource);
    var currentApi = ReadApi(newSource);
    if (oldApi.Count + currentApi.Count > 0) entries.Add((path, oldApi, currentApi));
}
var added = entries.Sum(entry => entry.Current.Select(api => api.Declaration).Except(entry.Old.Select(api => api.Declaration)).Count());
var removed = entries.Sum(entry => entry.Old.Select(api => api.Declaration).Except(entry.Current.Select(api => api.Declaration)).Count());
output.AppendLine("## Complete declaration delta").AppendLine();
output.AppendLine($"Baseline `{baseline}`; {entries.Count} changed public-source files, {added} added/replacement declarations, {removed} removed/replaced declarations.").AppendLine();
output.AppendLine("Generated from all current SDK source files, including untracked additions, and the baseline tree. Public/protected declarations include containing namespaces/types, overload parameters, required members, attributes, optional defaults, primary constructors and interface members. Compiler-synthesized/inherited members are represented by their source declarations, not expanded. Unchanged signatures in changed files are listed by containing type as behavior-review entries; the concept table above supplies their entry point, ownership, callers and tests. No source file is excluded by guessed file role.").AppendLine();
foreach (var entry in entries)
{
    var group = Group(entry.Path);
    output.AppendLine($"### {entry.Path}").AppendLine();
    output.AppendLine($"Concept/decision: [{group}](#{group}). Source: [{Path.GetFileName(entry.Path)}](../../../{entry.Path}).").AppendLine();
    var before = entry.Old.Select(api => api.Declaration).ToHashSet(StringComparer.Ordinal);
    var after = entry.Current.Select(api => api.Declaration).ToHashSet(StringComparer.Ordinal);
    var deleted = before.Except(after).Order(StringComparer.Ordinal).ToArray();
    var inserted = after.Except(before).Order(StringComparer.Ordinal).ToArray();
    if (deleted.Length == 0 && inserted.Length == 0)
        output.AppendLine($"Public signatures unchanged ({after.Count}); behavior reviewed under {group}.").AppendLine();
    else
    {
        output.AppendLine("```diff");
        foreach (var declaration in deleted) output.AppendLine($"- {declaration}");
        foreach (var declaration in inserted) output.AppendLine($"+ {declaration}");
        output.AppendLine("```").AppendLine();
    }
    output.AppendLine("Public owners: " + string.Join(", ", entry.Old.Concat(entry.Current).Select(api => $"`{api.Owner}`").Distinct().Order(StringComparer.Ordinal)) + ".").AppendLine();
}
var map = File.ReadAllText(mapPath);
var markerIndex = map.IndexOf(marker, StringComparison.Ordinal);
if (markerIndex < 0) throw new InvalidOperationException("API map generation marker is missing.");
var expected = map[..(markerIndex + marker.Length)] + "\n\n" + output.ToString().TrimEnd() + "\n";
if (args.Contains("--write")) File.WriteAllText(mapPath, expected, new UTF8Encoding(false));
else if (map != expected) throw new InvalidOperationException("API map is stale. Run this tool with --write after reviewing the new delta.");
Console.WriteLine($"API inventory: {entries.Count} changed public-source files; +{added}/-{removed} declarations; 0 unmapped files; {(args.Contains("--write") ? "written" : "current")}.");

string Git(params string[] arguments)
{
    var start = new ProcessStartInfo("git") { WorkingDirectory = root, RedirectStandardOutput = true, RedirectStandardError = true };
    foreach (var argument in arguments) start.ArgumentList.Add(argument);
    using var process = Process.Start(start)!;
    var text = process.StandardOutput.ReadToEnd();
    var error = process.StandardError.ReadToEnd();
    process.WaitForExit();
    if (process.ExitCode != 0) throw new InvalidOperationException(error);
    return text;
}

static bool IsSource(string path) => path.EndsWith(".cs", StringComparison.Ordinal) &&
    !path.Split('/').Any(segment => segment is "bin" or "obj");

static string Group(string path) => path switch
{
    var value when value.StartsWith("samples/") => "sample-runtime",
    var value when value.StartsWith("src/AAuth.Events/") => "events",
    var value when value.StartsWith("src/AAuth.R3/") => "r3",
    var value when value.Contains("/Discovery/") || value.EndsWith("/AAuthUrl.cs") || value.Contains("/Identifiers/") => "discovery",
    var value when value.Contains("/Crypto/") || value.Contains("/HttpSig/") || value.Contains("/Verification/") => "signatures",
    var value when value.Contains("/Tokens/") => "tokens",
    var value when value.Contains("/DependencyInjection/") => "di",
    var value when value.Contains("/Person/") || value.Contains("/Access/") || value.Contains("Consent") || value.Contains("DeferredState") => "consent",
    var value when value.Contains("/Server/ResourceManaged/") || value.Contains("OpaqueToken") || value.Contains("AAuthAccess") || value.Contains("AAuthRequestOptions") => "resource-managed",
    var value when value.Contains("Revocation") || value.Contains("JtiStore") || value.Contains("/TokenKey") || value.Contains("/TokenGrant") || value.Contains("/TokenRegistration") => "revocation",
    var value when value.Contains("Governance") || value.Contains("/CallChaining/") => "governance",
    var value when value.Contains("/Server/") || value.Contains("/Errors/") || value.Contains("/Headers/") || value.EndsWith("AAuthConstants.cs") => "server-contracts",
    var value when value.Contains("/Agent/") || value.EndsWith("Builder.cs") => "agent-clients",
    _ => throw new InvalidOperationException($"Unmapped public API file: {path}"),
};

static List<ApiEntry> ReadApi(string source)
{
    var tree = CSharpSyntaxTree.ParseText(source);
    var diagnostics = tree.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error).ToArray();
    if (diagnostics.Length > 0) throw new InvalidOperationException(string.Join("\n", diagnostics.Select(diagnostic => diagnostic.ToString())));
    var result = new List<ApiEntry>();
    foreach (var member in tree.GetRoot().DescendantNodes().OfType<MemberDeclarationSyntax>())
    {
        if (member is BaseNamespaceDeclarationSyntax || !Exported(member)) continue;
        var owner = string.Join(".", member.Ancestors().Reverse().Select(ancestor => ancestor switch
        {
            BaseNamespaceDeclarationSyntax space => space.Name.ToString(),
            BaseTypeDeclarationSyntax type => type.Identifier.Text,
            _ => null,
        }).Where(name => name is not null));
        var header = member switch
        {
            TypeDeclarationSyntax type => type.WithMembers(default).WithOpenBraceToken(default).WithCloseBraceToken(default).WithSemicolonToken(default),
            EnumDeclarationSyntax enumeration => enumeration.WithMembers(default).WithOpenBraceToken(default).WithCloseBraceToken(default).WithSemicolonToken(default),
            MethodDeclarationSyntax method => method.WithBody(null).WithExpressionBody(null).WithSemicolonToken(default),
            ConstructorDeclarationSyntax constructor => constructor.WithBody(null).WithExpressionBody(null).WithInitializer(null).WithSemicolonToken(default),
            DestructorDeclarationSyntax => null,
            OperatorDeclarationSyntax operation => operation.WithBody(null).WithExpressionBody(null).WithSemicolonToken(default),
            ConversionOperatorDeclarationSyntax conversion => conversion.WithBody(null).WithExpressionBody(null).WithSemicolonToken(default),
            PropertyDeclarationSyntax property => property.WithAccessorList(Accessors(property.AccessorList)).WithExpressionBody(null).WithSemicolonToken(default),
            IndexerDeclarationSyntax indexer => indexer.WithAccessorList(Accessors(indexer.AccessorList)).WithExpressionBody(null).WithSemicolonToken(default),
            EventDeclarationSyntax eventMember => eventMember.WithAccessorList(Accessors(eventMember.AccessorList)),
            _ => member,
        };
        if (header is null) continue;
        var declaration = string.Join(" ", header.DescendantTokens().Select(token => token.Text));
        result.Add(new(owner, $"{owner}: {declaration}"));
    }
    return result;
}

static AccessorListSyntax? Accessors(AccessorListSyntax? accessors) => accessors?.WithAccessors(
    SyntaxFactory.List(accessors.Accessors.Select(accessor => accessor.WithBody(null).WithExpressionBody(null)
        .WithSemicolonToken(SyntaxFactory.Token(SyntaxKind.SemicolonToken)))));

static bool Exported(MemberDeclarationSyntax member)
{
    if (member.Ancestors().OfType<BaseTypeDeclarationSyntax>().Any(type => !Accessible(type))) return false;
    return Accessible(member);
}

static bool Accessible(MemberDeclarationSyntax member)
{
    if (member.Modifiers.Any(SyntaxKind.PublicKeyword) || member.Modifiers.Any(SyntaxKind.ProtectedKeyword)) return true;
    return member.Parent is InterfaceDeclarationSyntax or EnumDeclarationSyntax &&
        !member.Modifiers.Any(SyntaxKind.PrivateKeyword) && !member.Modifiers.Any(SyntaxKind.InternalKeyword);
}

internal sealed record ApiEntry(string Owner, string Declaration);
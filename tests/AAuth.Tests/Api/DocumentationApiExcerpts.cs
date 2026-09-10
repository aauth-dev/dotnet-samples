using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Xunit;

namespace AAuth.Tests.Api;

internal static class DocumentationApiExcerpts
{
    private static readonly Lazy<BaseTypeDeclarationSyntax[]> Declarations = new(() =>
        Directory.EnumerateFiles(Path.Combine(DocumentationInventory.Root, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains("/obj/") && !path.Contains("/bin/"))
            .SelectMany(path => CSharpSyntaxTree.ParseText(File.ReadAllText(path)).GetRoot().DescendantNodes().OfType<BaseTypeDeclarationSyntax>()).ToArray());

    internal static bool IsExcerpt(string code)
    {
        var root = CSharpSyntaxTree.ParseText(code).GetCompilationUnitRoot();
        var types = root.DescendantNodes().OfType<BaseTypeDeclarationSyntax>().ToArray();
        return !root.Members.OfType<GlobalStatementSyntax>().Any() && types.Length > 0
            && types.All(type => Declarations.Value.Any(actual => actual.Identifier.Text == type.Identifier.Text));
    }

    internal static void Validate(string key, string code)
    {
        foreach (var type in CSharpSyntaxTree.ParseText(code).GetRoot().DescendantNodes().OfType<BaseTypeDeclarationSyntax>())
        {
            var actual = Declarations.Value.First(candidate => candidate.Identifier.Text == type.Identifier.Text);
            Assert.True(type.Modifiers.Any(SyntaxKind.SealedKeyword) == actual.Modifiers.Any(SyntaxKind.SealedKeyword), $"{key}: {type.Identifier} sealed modifier differs");
            if (type is EnumDeclarationSyntax enumeration)
            {
                foreach (var item in enumeration.Members)
                    Assert.Contains(((EnumDeclarationSyntax)actual).Members, member => member.Identifier.Text == item.Identifier.Text);
                continue;
            }
            if (type is not TypeDeclarationSyntax declaration || actual is not TypeDeclarationSyntax implementation) continue;
            foreach (var member in declaration.Members)
            {
                var name = member switch
                {
                    PropertyDeclarationSyntax property => property.Identifier.Text,
                    MethodDeclarationSyntax method => method.Identifier.Text,
                    ConstructorDeclarationSyntax constructor => constructor.Identifier.Text,
                    FieldDeclarationSyntax field => field.Declaration.Variables.First().Identifier.Text,
                    _ => null
                };
                if (name is null) continue;
                var candidates = implementation.Members.Where(candidate => candidate switch
                {
                    PropertyDeclarationSyntax property => property.Identifier.Text == name,
                    MethodDeclarationSyntax method => method.Identifier.Text == name,
                    ConstructorDeclarationSyntax constructor => constructor.Identifier.Text == name,
                    FieldDeclarationSyntax field => field.Declaration.Variables.Any(variable => variable.Identifier.Text == name),
                    _ => false
                }).ToArray();
                Assert.True(candidates.Length > 0, $"{key}: {type.Identifier}.{name} does not exist");
                if (member is PropertyDeclarationSyntax shown)
                    Assert.True(candidates.OfType<PropertyDeclarationSyntax>().Any(property => Normalize(property.Type) == Normalize(shown.Type)), $"{key}: {type.Identifier}.{name} property type differs");
                if (member is MethodDeclarationSyntax shownMethod)
                    Assert.True(candidates.OfType<MethodDeclarationSyntax>().Any(method => Normalize(method.ReturnType) == Normalize(shownMethod.ReturnType)
                        && method.ParameterList.Parameters.Select(parameter => Normalize(parameter.Type!)).SequenceEqual(shownMethod.ParameterList.Parameters.Select(parameter => Normalize(parameter.Type!)))),
                        $"{key}: {type.Identifier}.{name} signature differs");
            }
        }
    }

    internal static int ValidateTables(string file)
    {
        string? typeName = null;
        var tableKind = "";
        var checkedRows = 0;
        var failures = new List<string>();
        foreach (var line in File.ReadLines(Path.Combine(DocumentationInventory.Root, file)))
        {
            if (line.StartsWith("## ", StringComparison.Ordinal)) { typeName = null; tableKind = ""; }
            if (line.StartsWith("### ", StringComparison.Ordinal))
            {
                typeName = line[4..].Split(' ')[0];
                tableKind = "";
            }
            if (line.StartsWith("| Property | Type |", StringComparison.Ordinal)) tableKind = "property";
            if (line.StartsWith("| Parameter | Type |", StringComparison.Ordinal)) tableKind = "parameter";
            if (!line.StartsWith('|')) { tableKind = ""; continue; }
            if (tableKind.Length == 0 || !line.StartsWith("| `", StringComparison.Ordinal)) continue;
            var cells = line.Split('|').Select(cell => cell.Trim().Trim('`')).ToArray();
            var implementation = Declarations.Value.OfType<TypeDeclarationSyntax>().FirstOrDefault(type => type.Identifier.ValueText == typeName);
            var types = tableKind == "property"
                ? implementation?.Members.OfType<PropertyDeclarationSyntax>().Where(property => property.Identifier.ValueText == cells[1]).Select(property => property.Type)
                : implementation?.Members.OfType<ConstructorDeclarationSyntax>().SelectMany(constructor => constructor.ParameterList.Parameters)
                    .Where(parameter => parameter.Identifier.ValueText == cells[1]).Select(parameter => parameter.Type!);
            var candidates = types?.Select(Normalize).ToArray() ?? [];
            var documented = Normalize(SyntaxFactory.ParseTypeName(cells[2]));
            if (!candidates.Contains(documented))
                failures.Add($"{file}: {typeName}.{cells[1]} documents {cells[2]}; source: {string.Join(", ", candidates)}");
            checkedRows++;
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
        return checkedRows;
    }

    private sealed class UnqualifiedTypes : CSharpSyntaxRewriter
    {
        public override SyntaxNode? VisitQualifiedName(QualifiedNameSyntax node) => Visit(node.Right);
        public override SyntaxNode? VisitAliasQualifiedName(AliasQualifiedNameSyntax node) => Visit(node.Name);
    }

    private static string Normalize(TypeSyntax type) => string.Concat(new UnqualifiedTypes().Visit(type)!
        .DescendantTokens().Select(token => token.Text));
}
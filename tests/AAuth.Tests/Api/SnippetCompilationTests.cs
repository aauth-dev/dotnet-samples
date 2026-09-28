using System.Net;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Xunit;

namespace AAuth.Tests.Api;

public sealed class SnippetCompilationTests
{
    [Fact]
    public void Documentation_ResourceDiscoveryUsesOwnedAdmittedTransport()
    {
        var snippet = DocumentationInventory.Read().Single(snippet => snippet.File == "docs/server/resource-metadata.md"
            && snippet.Code.Contains("metadata.FetchAsync"));
        var creation = CSharpSyntaxTree.ParseText(snippet.Code).GetRoot().DescendantNodes()
            .OfType<ObjectCreationExpressionSyntax>().Single(expression => expression.Type.ToString() == "MetadataClient");
        Assert.Equal("cacheTtl", Assert.Single(creation.ArgumentList!.Arguments).NameColon!.Name.Identifier.ValueText);
        Assert.Contains("using var metadata", snippet.Code);
        Compile(snippet.Key, snippet.Code);
        using var metadata = new AAuth.Discovery.MetadataClient(cacheTtl: TimeSpan.FromMinutes(15));
        Assert.Same(AAuth.Discovery.AAuthEgressPolicy.Production, metadata.Policy);
        Assert.Equal("https://resource.example/.well-known/aauth-resource.json",
            metadata.GetUrl("https://resource.example", "aauth-resource.json").AbsoluteUri);
    }

    [Fact]
    public void Documentation_SigningAndReplayDescribeActualInputs()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/reference/configuration.md"));
        var signing = text.Split("### AAuthSigningHandler", StringSplitOptions.None)[1]
            .Split("### ISignatureKeyProvider Implementations", StringSplitOptions.None)[0];
        Assert.Contains("IAAuthKey", signing);
        Assert.Contains("provider does not supply the private key", signing);
        foreach (var name in new[] { "Label", "Capabilities", "OnSignatureBase" })
        {
            Assert.Contains(name, signing);
            Assert.NotNull(typeof(AAuth.HttpSig.AAuthSigningHandler).GetProperty(name));
        }
        var resourceOptions = File.ReadAllText(Path.Combine(RepositoryRoot(), "src/AAuth/DependencyInjection/AAuthResourceOptions.cs"));
        Assert.DoesNotContain("JTI-based replay", resourceOptions);
        Assert.Contains("canonical signature base", resourceOptions);
        var resourceGuide = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/server/resource-metadata.md"));
        Assert.Contains("`RevocationEndpoint` is also available through `AAuthResourceOptions`", resourceGuide);
    }

    [Theory]
    [InlineData("docs/reference/configuration.md", 100)]
    [InlineData("docs/reference/dependency-injection.md", 20)]
    [InlineData("docs/server/token-issuance.md", 13)]
    public void Documentation_ReferenceTablesMatchSource(string file, int minimumRows)
    {
        Assert.True(DocumentationApiExcerpts.ValidateTables(file) >= minimumRows);
    }

    [Fact]
    public void Documentation_ReplaySeparatesSignaturesFromTokenRevocation()
    {
        var overview = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/signing-modes/overview.md"));
        foreach (var concept in new[] { "freshness", "replay cache" })
        {
            var row = overview.Split('\n').Single(line => line.StartsWith('|') && line.Contains(concept, StringComparison.OrdinalIgnoreCase));
            var cells = row.Split('|');
            Assert.Equal("—", cells[2].Trim());
            Assert.All(cells.Skip(3).Take(3), cell => Assert.Equal("✓", cell.Trim()));
        }
        Assert.DoesNotMatch(@"(?i)\|[^\r\n|]*replay[^\r\n|]*jti", overview);
        Assert.Matches(@"(?is)revocation.{0,80}issuer.{0,20}`jti`", overview);
        Assert.Matches(@"(?is)token.{0,40}reusable.{0,30}fresh", overview);
    }

    [Theory]
    [InlineData("docs/reference/configuration.md")]
    [InlineData("docs/reference/dependency-injection.md")]
    [InlineData("docs/server/resource-metadata.md")]
    public void Documentation_ProactiveEndpointIsNotTokenRecipient(string file)
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), file));
        var rows = text.Split('\n').Where(line => line.StartsWith("| `AuthorizationEndpoint` |", StringComparison.Ordinal)).ToArray();
        Assert.NotEmpty(rows);
        foreach (var row in rows)
        {
            Assert.Matches(@"(?i)resource.{0,20}proactive", row);
            Assert.Contains("PersonServerAudience", row);
            Assert.DoesNotMatch(@"(?i)(AS authorization URL|Access Server's authorization)", row);
        }
        Assert.DoesNotMatch(@"(?i)(AuthorizationEndpoint\s*=|""authorization_endpoint""\s*:)\s*""https://as\.example", text);
    }

    [Fact]
    public void Documentation_TokenBuildersUseAlgorithmAgileKeys()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/server/token-issuance.md"));
        var overview = text.Split("## Overview", StringSplitOptions.None)[1].Split("## Resource Tokens", StringSplitOptions.None)[0];
        Assert.Contains("IAAuthKey", overview);
        Assert.Contains("Ed25519", overview);
        Assert.Contains("ES256", overview);
        foreach (var builder in new[] { typeof(AAuth.Tokens.AgentTokenBuilder), typeof(AAuth.Tokens.AuthTokenBuilder), typeof(AAuth.Tokens.ResourceTokenBuilder) })
            Assert.Equal(typeof(AAuth.Crypto.IAAuthKey), builder.GetProperty("Key")!.PropertyType);
        Assert.DoesNotMatch(@"(?i)each produces[^\r\n]*signed with Ed25519", overview);
    }

    [Fact]
    public void Documentation_AgentTokenDiscoveryAndResourceKeysMatchSource()
    {
        var overview = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/signing-modes/overview.md"));
        var row = overview.Split('\n').Single(line => line.StartsWith("| Remote key discovery (JWKS) |"));
        Assert.Equal("✓ (cached)", row.Split('|')[5].Trim());
        Assert.Contains("embedded `cnf.jwk`", overview);
        var verifier = CSharpSyntaxTree.ParseText(File.ReadAllText(Path.Combine(RepositoryRoot(), "src/AAuth/Tokens/TokenVerifier.cs")))
            .GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>().Single(method => method.Identifier.ValueText == "VerifyWithJwksAsync");
        Assert.Contains("metadata.FetchAsync", verifier.ToString());
        Assert.Contains("jwks.ResolveKeyAsync", verifier.ToString());
        var options = new AAuth.AAuthResourceOptions { Issuer = "https://resource.test" };
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        Microsoft.Extensions.DependencyInjection.AAuthResourceServiceCollectionExtensions.AddAAuthResource(services, configured => configured.Issuer = options.Issuer);
        Assert.Empty(options.SigningKeys);
        var dependencyInjection = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/reference/dependency-injection.md"));
        Assert.Contains("verification-only resource can leave `SigningKeys` empty", dependencyInjection);
        Assert.DoesNotContain("requires the resource issuer and signing keys", dependencyInjection);
    }

    [Fact]
    public void Documentation_EnrollmentKeyAndResourceRegistrationAreDistinct()
    {
        var gettingStarted = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/getting-started.md"));
        Assert.DoesNotContain("AP-internal JWT", gettingStarted);
        Assert.Contains("per-agent JWKS", gettingStarted);
        var provider = File.ReadAllText(Path.Combine(RepositoryRoot(), "src/AAuth/Agent/AgentProviderClient.cs"));
        Assert.DoesNotContain("AP-internal JWT", provider);
        Assert.Contains("not the AP's token-signing", provider);
        var dependencyInjection = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/reference/dependency-injection.md"));
        var resource = dependencyInjection.Split("### AAuthResourceOptions", StringSplitOptions.None)[1]
            .Split("### AAuthDiscoveryOptions", StringSplitOptions.None)[0];
        Assert.DoesNotContain("Registration requires an agent token", resource);
        Assert.Contains("does not require agent credentials", resource);
    }

    [Fact]
    public void Documentation_ProviderTableConstructorsCompile()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs/reference/configuration.md"));
        var section = text.Split("### ISignatureKeyProvider Implementations", StringSplitOptions.None)[1]
            .Split("## Dependency Injection Options", StringSplitOptions.None)[0];
        var rows = Regex.Matches(section, @"\| `(?<provider>\w+SignatureKeyProvider)` \| `(?<parameters>[^`]+)` \|");
        Assert.Equal(5, rows.Count);
        foreach (Match row in rows)
        {
            var parameters = row.Groups["parameters"].Value;
            var arguments = string.Join(", ", SyntaxFactory.ParseParameterList("(" + parameters + ")").Parameters
                .Select(parameter => parameter.Identifier.ValueText + ": " + parameter.Identifier.ValueText));
            Compile(row.Groups["provider"].Value,
                $"public static void Example({parameters}) {{ _ = new {row.Groups["provider"].Value}({arguments}); }}", member: true);
        }
        Assert.DoesNotContain("omit for HWK", text);
        Assert.Contains("Omitting credentials does not select HWK", text);
    }

    [Fact]
    public void Documentation_ManualNamingJwtSignerSelectsEphemeralKey()
    {
        var snippet = DocumentationInventory.Read().Single(snippet => snippet.File == "docs/signing-modes/overview.md"
            && snippet.Code.Contains("ISignatureKeyProvider provider"));
        var declarations = CSharpSyntaxTree.ParseText(snippet.Code).GetRoot().DescendantNodes()
            .OfType<VariableDeclaratorSyntax>().ToDictionary(declaration => declaration.Identifier.ValueText);
        var selection = Assert.IsType<ConditionalExpressionSyntax>(declarations["signingKey"].Initializer!.Value);
        Assert.Equal("mode == \"jkt-jwt\"", selection.Condition.ToString());
        Assert.Equal("ephemeralKey", selection.WhenTrue.ToString());
        Assert.Equal("key", selection.WhenFalse.ToString());
        var handler = Assert.IsType<ObjectCreationExpressionSyntax>(declarations["handler"].Initializer!.Value);
        Assert.Equal("signingKey", handler.ArgumentList!.Arguments[0].Expression.ToString());
        Compile(snippet.Key, snippet.Code);
    }

    [Fact]
    public void Documentation_ResourceRecipientsAndGenericRoutesUseCorrectContext()
    {
        var snippets = DocumentationInventory.Read();
        var issuance = snippets.Where(snippet => snippet.File == "docs/server/token-issuance.md").Select(snippet => snippet.Code).ToArray();
        Assert.Contains(issuance, code => code.Contains("expectedPersonServer: psIssuer")
            && code.Contains("VerifyPresentedTokenAsync"));
        Assert.Contains(issuance, code => code.Contains("expectedPersonServer: authenticatedPsIdentifier")
            && code.Contains("VerifyPresentedTokenAsync")
            && code.Contains("issuance.ValidateResourceContext(verified.Payload)"));
        Assert.DoesNotContain(issuance, code => code.Contains("expectedApprover"));
        var routes = snippets.Single(snippet => snippet.File == "docs/server/verification-middleware.md"
            && snippet.Code.Contains("MapGet(\"/pseudonymous\""));
        Assert.Contains("MapGet(\"/pseudonymous\", handler).RequireGenericSignature()", routes.Code);
        Assert.Contains("MapGet(\"/identified\", handler).RequireGenericSignature(identified: true)", routes.Code);
        var verifier = CSharpSyntaxTree.ParseText(File.ReadAllText(Path.Combine(RepositoryRoot(), "src/AAuth/Tokens/TokenVerifier.cs")))
            .GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>().Single(method => method.Identifier.ValueText == "VerifyResourceTokenAsync");
        var documentation = verifier.GetLeadingTrivia().ToFullString();
        Assert.DoesNotContain("without a mission constraint pass", documentation);
        Assert.Contains("VerifyPresentedTokenAsync", documentation);
        Assert.DoesNotContain("expectedApprover", documentation);
        var profile = File.ReadAllText(Path.Combine(RepositoryRoot(), "samples/MockResourceServers/Profile/Program.cs"));
        Assert.DoesNotContain("RequireAAuthSignature", profile);
        Assert.DoesNotContain("no JWT issuer check", profile);
        Assert.DoesNotContain("no JWT\n// issuer verification", profile);
        Assert.Contains("JWT issuer verification still applies", profile);
    }

    [Fact]
    public void Documentation_FrozenSurface()
    {
        var results = new List<(DocumentationSnippet Snippet, string Status)>();
        var failures = new List<string>();
        foreach (var snippet in DocumentationInventory.Read())
        {
            try { results.Add((snippet, CheckSnippet(snippet))); }
            catch (Exception exception) { failures.Add($"{snippet.Key}: {exception.Message}"); }
        }
        File.WriteAllLines(Path.Combine(Path.GetTempPath(), "aauth-phase13-surface-failures.txt"), failures);
        Assert.True(failures.Count == 0, string.Join("\n", failures));
        var appendix = new System.Text.StringBuilder("\n\n## Complete Inventory\n\n");
        appendix.AppendLine($"{DocumentationInventory.Files().Count()} files; {results.Count} blocks. Counts by validation class:\n");
        foreach (var group in results.GroupBy(result => result.Status).OrderBy(group => group.Key))
            appendix.AppendLine($"- {group.Count()}: {group.Key}");
        appendix.AppendLine("\n| File | SHA-256 | Blocks | Check |\n|---|---|---|---|");
        foreach (var file in DocumentationInventory.Files().Order())
        {
            var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path.Combine(RepositoryRoot(), file))));
            appendix.AppendLine($"| [{file}](../../../{file}) | `{hash}` | {results.Count(result => result.Snippet.File == file)} | Frozen source; links/patterns; blocks below; capability matrix for runtime/browser evidence |");
        }
        appendix.AppendLine("\n| Source Block | Format | SHA-256 | Result | Source and Behavior Evidence |\n|---|---|---|---|---|");
        foreach (var (snippet, status) in results)
            appendix.AppendLine($"| [{snippet.Key}](../../../{snippet.File}#L{snippet.Line}) | {snippet.Language} | `{snippet.Hash}` | {status} | {EvidenceFor(snippet.File)} |");
        var report = appendix.ToString();
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "aauth-phase13-docs-surface.md"), report);
        var mapPath = Path.Combine(RepositoryRoot(), ".agent/plans/2026-09-11-aauth-v11-spec-migration/docs-surface-map.md");
        var existing = File.ReadAllText(mapPath);
        const string marker = "<!-- generated-docs-surface -->";
        var expected = existing[..(existing.IndexOf(marker, StringComparison.Ordinal) + marker.Length)] + report;
        if (Environment.GetEnvironmentVariable("AAUTH_UPDATE_DOCS_INVENTORY") == "1") File.WriteAllText(mapPath, expected);
        else Assert.True(existing == expected, "Documentation inventory is stale; regenerate only after reviewing changed surfaces.");
    }

    private static string CheckSnippet(DocumentationSnippet snippet)
    {
        if (snippet.Language == "csharp")
        {
            if (!CSharpSyntaxTree.ParseText(snippet.Code).GetCompilationUnitRoot().Members.Any())
                return "C# comment-only narrative: reviewed against the associated scenario; no executable statements";
            if (ExternalTemplate(snippet) is { } external)
            {
                Assert.DoesNotContain(CSharpSyntaxTree.ParseText(snippet.Code).GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
                return external;
            }
            if (DocumentationApiExcerpts.IsExcerpt(snippet.Code))
            {
                DocumentationApiExcerpts.Validate(snippet.Key, snippet.Code);
                return "API excerpt: source member/type/sealed checks; not executable";
            }
            var context = snippet.Id.StartsWith("SignedGetJwksUri-") ? "private EnrollResult result = null!;"
                : snippet.Id.StartsWith("MissionPollPermission-") ? "private PermissionResult result = null!;" : "";
            Compile(snippet.Key, snippet.Code, member: snippet.Code.TrimStart().StartsWith("public static"), context: context);
            return "Exact C# compiled with typed prior-step/host inputs";
        }
        if (snippet.Language == "dynamic") return "Dynamic Razor binding: build plus mapped scenario browser/captured-wire tests";
        if (snippet.Language == "inline-code")
        {
            Assert.DoesNotMatch(@"(?i)^(EdDSA|signatureOnly|error_description)$", snippet.Code.Trim());
            return "Inline Razor label/expression: source inventory, build and scenario display checks; not a standalone program";
        }
        if (snippet.Language == "json")
        {
            var json = snippet.Code.Trim();
            using var parsed = System.Text.Json.JsonDocument.Parse(json.StartsWith('"') ? "{" + json + "}" : json);
            return json.StartsWith('"') ? "JSON member fragment parsed inside an explicit object" : "JSON parsed; displayed identifiers/claims are illustrative";
        }
        if (snippet.Language is "bash" or "sh")
        {
            var makefile = File.ReadAllText(Path.Combine(RepositoryRoot(), "Makefile"));
            foreach (Match command in Regex.Matches(snippet.Code, @"\bmake\s+(?<target>[a-zA-Z][a-zA-Z0-9_-]*)"))
                Assert.Matches($@"(?m)^{Regex.Escape(command.Groups["target"].Value)}(?:\s|:)", makefile);
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("bash", "-n")
            { RedirectStandardInput = true, RedirectStandardError = true, UseShellExecute = false })!;
            process.StandardInput.Write(snippet.Code);
            process.StandardInput.Close();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, error);
            return "Shell syntax checked; side-effect commands not executed";
        }
        if (snippet.Language == "mermaid")
        {
            Assert.Matches(@"^\s*(sequenceDiagram|flowchart|graph)\b", snippet.Code);
            return "Sequence/flow source checked; actors/order reviewed against mapped scenario";
        }
        if (snippet.Language == "string" && System.Text.RegularExpressions.Regex.IsMatch(snippet.Code, @"^\s*(PRAGMA|SELECT|INSERT)\b"))
            return "SQL runtime literal: sample build and Events HTTP/persistence tests";
        if (snippet.Language is "http" or "text" or "")
        {
            Assert.DoesNotMatch(@"(?i)(error_description|sig=hwk;[^\r\n]*jwk=|alg=""EdDSA"")", snippet.Code);
            var bodyOffset = snippet.Code.IndexOf("\n\n", StringComparison.Ordinal);
            if (bodyOffset >= 0 && snippet.Code[(bodyOffset + 2)..].TrimStart().StartsWith('{'))
            {
                var body = System.Text.Json.Nodes.JsonNode.Parse(snippet.Code[(bodyOffset + 2)..]);
                Assert.NotNull(body);
                if (snippet.Code.Contains("application/problem+json")) Assert.NotNull(body["error"]);
                if (body["jti"] is not null)
                {
                    Assert.True(JtiBodyExamples.TryGetValue(snippet.Key, out var members),
                        $"{snippet.Key} carries a jti body but has no explicit HTTP example classification.");
                    Assert.Equal(members.Order(StringComparer.Ordinal), body.AsObject().Select(member => member.Key).Order(StringComparer.Ordinal));
                }
            }
            foreach (Match header in Regex.Matches(snippet.Code, @"(?m)^AAuth-Requirement:\s*(?<value>[^\r\n]+)"))
            {
                var requirement = AAuth.Headers.AAuthRequirementHeader.Parse(header.Groups["value"].Value);
                Assert.NotNull(requirement);
            }
            foreach (Match location in Regex.Matches(snippet.Code, @"(?m)^Location:\s*(?<value>[^\r\n]+)"))
                Assert.True(Uri.TryCreate(location.Groups["value"].Value, UriKind.Absolute, out _), "Location example must be absolute.");
            return "Illustrative text/HTTP fragment: placeholder bytes, current contract check; not a signed request";
        }
        throw new InvalidOperationException($"Unclassified {snippet.Language} block");
    }

    private static readonly string[] RevocationRequestMembers = ["jti", "exp"];

    private static readonly Dictionary<string, string[]> JtiBodyExamples = new(StringComparer.Ordinal)
    {
        ["docs/server/replay-detection.md:fence-5"] = RevocationRequestMembers,
    };

    private static string EvidenceFor(string file)
    {
        if (file.Contains("Catalog", StringComparison.OrdinalIgnoreCase) || file.Contains("catalog-gateway"))
            return "[Catalog session](../../../samples/CapabilitySupport/CatalogDemoSession.cs), [both-app Catalog wrapper](../../../tests/e2e/helpers/catalog.ts), R3VocabularyTests";
        if (file.Contains("Wallet", StringComparison.OrdinalIgnoreCase) || file.Contains("wallet-protocol"))
            return "[Wallet session](../../../samples/CapabilitySupport/WalletDemoSession.cs), [both-app Wallet wrapper](../../../tests/e2e/helpers/wallet-protocol.ts), DeferredFederationTests / RevocationLifecycleTests";
        if (file.Contains("Event", StringComparison.OrdinalIgnoreCase))
            return "[Event session](../../../samples/EventSupport/EventDemoSession.cs), [both-app Events wrapper](../../../tests/e2e/helpers/events.ts), EventHttpTests / EventPersistenceTests";
        if (file.Contains("GuidedTour") || file.Contains("SampleApp"))
            return "[capability-to-flow/spec map](capability-scenarios.md), [tour state](../../../samples/GuidedTour/TourSession.cs), [app specs](../../../samples/SampleApp/playwright-tests/), [tour specs](../../../samples/GuidedTour/playwright-tests/)";
        return "[API owning-source map](api-surface-map.md), [section-specific source/tests](conformance-ledger.md), [exact compiler](../../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs)";
    }

    [Fact]
    public void Documentation_InventoryDiscovery()
    {
        var snippets = DocumentationInventory.Read();
        var report = string.Join("\n", snippets.Select(snippet => $"{snippet.Key}\t{snippet.Language}\t{snippet.Line}\t{snippet.Code.Replace('\n', ' ')[..Math.Min(100, snippet.Code.Length)]}"));
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "aauth-phase13-inventory.tsv"), report);
        Assert.Equal(snippets.Count, snippets.Select(snippet => snippet.Key).Distinct().Count());
        Assert.Contains(snippets, snippet => snippet.File.EndsWith("TourSession.cs"));
        Assert.Contains(snippets, snippet => snippet.Language == "dynamic");
    }

    private static readonly MetadataReference[] References = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
        .Split(Path.PathSeparator).Concat(Directory.EnumerateFiles(AppContext.BaseDirectory, "*.dll"))
        .GroupBy(Path.GetFileName).Select(group => MetadataReference.CreateFromFile(group.First())).ToArray();

    public static IEnumerable<object[]> GuidedTourSnippets()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "samples/GuidedTour/CodeSnippets.cs"));
        return CSharpSyntaxTree.ParseText(source).GetRoot().DescendantNodes()
            .OfType<VariableDeclaratorSyntax>()
            .Where(declaration => declaration.Initializer?.Value is LiteralExpressionSyntax literal
                && literal.IsKind(SyntaxKind.StringLiteralExpression))
            .Select(declaration => new object[] { declaration.Identifier.Text });
    }

    [Theory]
    [MemberData(nameof(GuidedTourSnippets))]
    public void GuidedTour_ExactSnippetCompiles(string name)
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "samples/GuidedTour/CodeSnippets.cs"));
        var variable = CSharpSyntaxTree.ParseText(source).GetRoot().DescendantNodes()
            .OfType<VariableDeclaratorSyntax>().Single(declaration => declaration.Identifier.Text == name);
        var literal = Assert.IsType<LiteralExpressionSyntax>(variable.Initializer!.Value);
        var context = name == "SignedGetJwksUri" ? "private EnrollResult result = null!;"
            : name == "MissionPollPermission" ? "private PermissionResult result = null!;" : "";
        Compile(name, literal.Token.ValueText, context: context);
    }

    public static IEnumerable<object[]> RazorSnippets() => DocumentationInventory.Read()
        .Where(snippet => snippet.File.EndsWith(".razor") && snippet.Id.StartsWith("pre-") && snippet.Language == "csharp")
        .Select(snippet => new object[] { snippet.Key, snippet.Code });

    [Theory]
    [MemberData(nameof(RazorSnippets))]
    public void SampleApp_ExactRazorSnippetCompiles(string name, string snippet)
    {
        Compile(name, snippet);
    }

    [Fact]
    public void Documentation_CompilationProbe()
    {
        var failures = new List<string>();
        var passed = new List<string>();
        foreach (var snippet in DocumentationInventory.Read().Where(snippet => snippet.File.EndsWith(".md") && snippet.Language == "csharp"))
        {
            try
            {
                if (ExternalTemplate(snippet) is not null)
                    Assert.DoesNotContain(CSharpSyntaxTree.ParseText(snippet.Code).GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
                else if (DocumentationApiExcerpts.IsExcerpt(snippet.Code)) DocumentationApiExcerpts.Validate(snippet.Key, snippet.Code);
                else Compile(snippet.Key, snippet.Code);
                passed.Add(snippet.Key);
            }
            catch (Xunit.Sdk.XunitException exception) { failures.Add(snippet.Key + "\n" + exception.Message); }
        }
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "aauth-phase13-doc-compile.txt"), string.Join("\n", failures));
        File.WriteAllLines(Path.Combine(Path.GetTempPath(), "aauth-phase13-doc-passed.txt"), passed);
        Assert.Empty(failures);
    }

    internal static string? ExternalTemplate(DocumentationSnippet snippet) => snippet.File switch
    {
        "docs/advanced/key-management.md" when snippet.Code.Contains("class AzureKeyVaultStore") =>
            "External template: Azure.Security.KeyVault.Secrets/Azure.Core required; exportable Ed25519 secrets, not HSM signing; syntax checked only.",
        "docs/advanced/observability.md" when snippet.Code.Contains("AddOpenTelemetry") =>
            "External template: OpenTelemetry.Extensions.Hosting and Instrumentation.AspNetCore required; syntax checked, exporter not executed.",
        "docs/advanced/platform-attestation.md" when snippet.Code.Contains("WebAuthnAttestor") || snippet.Code.Contains("AppAttestAttestor") =>
            "Illustrative platform adapter: IWebAuthnService/DeviceCheck are host placeholders; IPlatformAttestor signature checked separately; no hardware or AP challenge/retry claim.",
        _ => null
    };

    [Theory]
    [InlineData(AAuth.Samples.Capabilities.WalletFlow.Clarification)]
    [InlineData(AAuth.Samples.Capabilities.WalletFlow.DirectAs)]
    [InlineData(AAuth.Samples.Capabilities.WalletFlow.Revocation)]
    public void Wallet_ExactDisplayedSnippetCompiles(AAuth.Samples.Capabilities.WalletFlow flow)
        => Compile(flow.ToString(), AAuth.Samples.Capabilities.WalletScenarioCode.For(flow), member: true);

    [Fact]
    public void Catalog_ExactDisplayedSnippetCompiles()
        => Compile("Catalog", AAuth.Samples.Capabilities.CatalogWalkthrough.Example, member: true);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void Documents_ExactDisplayedStepCompiles(int step)
        => Compile("Documents step " + step, AAuth.Samples.Capabilities.DocumentWalkthrough.Examples[step - 1], member: true);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    public void Events_ExactDisplayedStepCompiles(int step)
        => Compile("Events step " + step, AAuth.Samples.Events.EventDemoCode.Steps[step - 1], member: true);

    private static void Compile(string name, string snippet, bool member = false, string context = "")
    {
        var parsed = CSharpSyntaxTree.ParseText(snippet).GetCompilationUnitRoot();
        var imports = string.Join("\n", parsed.Usings.Select(directive => directive.ToFullString()));
        snippet = parsed.RemoveNodes(parsed.Usings, SyntaxRemoveOptions.KeepNoTrivia)!.ToFullString();
        var types = parsed.Members.Where(declaration => declaration is BaseTypeDeclarationSyntax).ToArray();
        if (types.Length > 0)
        {
            var snippetRoot = CSharpSyntaxTree.ParseText(snippet).GetCompilationUnitRoot();
            snippet = snippetRoot.RemoveNodes(snippetRoot.Members.OfType<BaseTypeDeclarationSyntax>(), SyntaxRemoveOptions.KeepNoTrivia)!.ToFullString();
        }
        var hasReturn = parsed.DescendantNodes().OfType<ReturnStatementSyntax>().Any(statement => statement.Expression is not null
            && !statement.Ancestors().Any(ancestor => ancestor is AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax or BaseMethodDeclarationSyntax));
        var source = imports + "\n" + DocumentationSnippetContext.Imports + "\n" + """
            using System;
            using System.Net;
            using System.Diagnostics;
            using System.Text.Json.Nodes;
            using System.Linq;
            using System.Net.Http;
            using System.Net.Http.Json;
            using System.Net.Http.Headers;
            using System.Threading;
            using System.Threading.Tasks;
            using AAuth;
            using AAuth.Agent;
            using AAuth.Agent.Governance;
            using AAuth.Crypto;
            using AAuth.Discovery;
            using AAuth.Headers;
            using AAuth.HttpSig;
            using AAuth.Server;
            using AAuth.Server.Verification;
            using AAuth.Tokens;
            using AAuth.R3;
            using AAuth.R3.Model;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.Extensions.Configuration;
            using Microsoft.Extensions.DependencyInjection;
            internal static class SampleEgress
            {
                internal static AAuthEgressPolicy Policy => AAuthEgressPolicy.Production;
            }
            public sealed class SnippetContext : ControllerBase
            {
                private AAuthKey key = AAuthKey.Generate();
                private AAuthKey resourceKey = AAuthKey.Generate();
                private IKeyStore keyStore = new InMemoryKeyStore();
                private string refreshEndpoint = "https://ap.example/refresh";
                private string apRefreshEndpoint = "https://ap.example/refresh";
                private AAuthKey publishedKey = AAuthKey.Generate();
                private string publishedKeyId = "published-key";
                private IConfiguration configuration = null!;
                private string localKeyHandle = "key";
                private string authToken = "held-auth-token";
                private string elevatedAuthToken = "held-elevated-token";
                private string resourceToken = "held-resource-token";
                private string issuer = "https://agent.example";
                private string agentId = "aauth:agent@agent.example";
                private string keyId = "key";
                private string personServer = "https://ps.example";
                private string resourceUrl = "https://resource.example/data";
                private string elevatedUrl = "https://resource.example/elevated";
                private string bookings = "https://bookings.example";
                private string account = "personal";
                private string[] messages = [];
                private System.Collections.Generic.IReadOnlySet<string> trustedPersonServers = new System.Collections.Generic.HashSet<string> { "https://ps.example" };
                private HttpClient client = null!;
                private HttpClient signedClient = null!;
                private HttpClient elevatedClient = null!;
                private HttpResponseMessage response = null!;
                private MetadataClient metadata = null!;
                private Interaction interaction = null!;
                private Uri pendingUri = null!;
                private string missionPendingUrl = "https://ps.example/pending/id";
                private string missionHeaderS256 = "held-mission-digest";
                private string s256 = "held-mission-digest";
                private string token68 = "held-opaque-token";
                private Mission mission = null!;
                private MissionSession session = null!;
                private MissionTool addToCalendarTool = new("add_to_calendar");
                private AAuthKey durableKey = null!;
                private AAuthKey ephemeralKey = null!;
                private AAuthKey myKey = null!;
                private string myIssuer = "https://intermediary.example";
                private string myAgentId = "aauth:agent@intermediary.example";
                private string psUrl = "https://ps.example";
                private HttpContext httpContext = null!;
                private Task SurfaceToUser(Interaction interaction, CancellationToken cancellationToken) => Task.CompletedTask;
                private TokenExchangeClient exchange = null!;
                private SampleApp.EnrollmentService Enrollment = null!;
                private IConfiguration Config = null!;
                private SampleApp.SelfIssuedIdentity _identity = null!;
                private GuidedTour.TourAgentIdentity _selfIdentity = null!;
                private GuidedTour.TourOptions _options = null!;
                private WebApplicationBuilder builder = null!;
            """ + context + DocumentationSnippetContext.Fields
            + (hasReturn ? "public async Task<object?> RunAsync() {\n" : "public async Task RunAsync() {\n")
            + (member ? "\n}\n" + snippet + "\n}" : "\n" + snippet + (hasReturn ? "\nreturn null;" : "") + "\n}}")
            + string.Join("\n", types.Select(declaration => declaration.ToFullString()));
        var compilation = CSharpCompilation.Create($"Snippet_{Regex.Replace(name, "[^a-zA-Z0-9_]", "_")}", [CSharpSyntaxTree.ParseText(source)], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        using var assembly = new MemoryStream();
        var result = compilation.Emit(assembly);
        Assert.True(result.Success, $"{name}:\n" + string.Join("\n", result.Diagnostics
            .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error)));
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "AAuth.slnx"))) return directory.FullName;
        throw new InvalidOperationException("Repository root was not found.");
    }

    [Theory]
    [InlineData("workflows/resource-managed-access.md", "var enrollment =")]
    [InlineData("workflows/bootstrap-enrollment.md", "var refreshed =")]
    [InlineData("workflows/identity-based-access.md", "SelfIssuing(publishedKey)")]
    [InlineData("workflows/ps-asserted-access.md", "AAuthClientBuilder.Enrolled(key)")]
    [InlineData("workflows/call-chaining.md", "AAuthClientBuilder.Enrolled(key)")]
    public void Documentation_ExactRevisedTemplateCompiles(string path, string selector)
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", path));
        var snippets = Regex.Matches(source, "```csharp\\r?\\n(?<code>.*?)```", RegexOptions.Singleline);
        var snippet = snippets.Single(match => match.Groups["code"].Value.Contains(selector, StringComparison.Ordinal));
        Compile(Path.GetFileNameWithoutExtension(path), snippet.Groups["code"].Value);
    }
}
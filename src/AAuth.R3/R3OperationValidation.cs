using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Supplies the authoritative operation identities for an R3 vocabulary.</summary>
public interface IR3AuthoritativeDefinitionProvider
{
    ValueTask<IReadOnlyList<R3OperationIdentity>> GetOperationsAsync(string vocabulary, CancellationToken cancellationToken = default);
}

/// <summary>Validates R3 documents and proposals against an authoritative operation definition.</summary>
public interface IR3OperationValidator
{
    ValueTask ValidateReferenceAsync(string r3Uri, string r3S256, CancellationToken cancellationToken = default);
    ValueTask ValidateDocumentAsync(R3Document document, CancellationToken cancellationToken = default);
    ValueTask ValidateProposalAsync(R3ProposalDocument proposal, CancellationToken cancellationToken = default);
}

/// <summary>Static authoritative operation provider for resources with in-process definitions.</summary>
public sealed class StaticR3AuthoritativeDefinitionProvider(IEnumerable<R3OperationIdentity> operations) : IR3AuthoritativeDefinitionProvider
{
    private readonly IReadOnlyList<R3OperationIdentity> _operations = operations.ToArray();

    public ValueTask<IReadOnlyList<R3OperationIdentity>> GetOperationsAsync(string vocabulary, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(vocabulary);
        return ValueTask.FromResult<IReadOnlyList<R3OperationIdentity>>(
            _operations.Where(operation => operation.Vocabulary == vocabulary).ToArray());
    }
}

/// <summary>Default R3 operation validator backed by the resource's proposal/document store.</summary>
public sealed class R3OperationValidator(
    R3ProposalStore store,
    IR3AuthoritativeDefinitionProvider provider,
    R3VocabularySchemas? schemas = null) : IR3OperationValidator
{
    private readonly R3VocabularySchemas _schemas = schemas ?? R3VocabularySchemas.Standard;

    public ValueTask ValidateReferenceAsync(string r3Uri, string r3S256, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(r3Uri);
        ArgumentException.ThrowIfNullOrEmpty(r3S256);
        if (!store.TryGet(r3S256, out var bytes))
            throw new InvalidOperationException("R3 reference cannot be validated because the document is not known.");
        R3Hash.Verify(bytes, r3S256);
        if (IsProposal(bytes))
            return ValidateProposalAsync(R3ProposalDocument.FromUtf8Bytes(bytes, schemas: _schemas), cancellationToken);
        return ValidateDocumentAsync(R3Document.FromUtf8Bytes(bytes, schemas: _schemas), cancellationToken);
    }

    public async ValueTask ValidateDocumentAsync(R3Document document, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        document.Validate(_schemas);
        var authoritative = await provider.GetOperationsAsync(document.Vocabulary, cancellationToken).ConfigureAwait(false);
        R3OperationValidation.ValidateGrant(new R3Grant { Vocabulary = document.Vocabulary, Operations = document.Operations }, authoritative, _schemas);
    }

    public async ValueTask ValidateProposalAsync(R3ProposalDocument proposal, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proposal);
        proposal.Validate(_schemas);
        var authoritative = await provider.GetOperationsAsync(proposal.Vocabulary, cancellationToken).ConfigureAwait(false);
        R3OperationValidation.ValidateGrant(new R3Grant { Vocabulary = proposal.Vocabulary, Operations = proposal.Operations }, authoritative, _schemas);
    }

    private static bool IsProposal(byte[] bytes)
    {
        using var json = System.Text.Json.JsonDocument.Parse(bytes);
        return json.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object
            && json.RootElement.TryGetProperty("parameters", out _);
    }
}

public static class R3OperationValidation
{
    public static void ValidateGrant(R3Grant grant, IEnumerable<R3OperationIdentity> authoritativeOperations,
        R3VocabularySchemas? schemas = null)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(authoritativeOperations);
        grant.Validate(allowEmpty: false, schemas);
        var authoritative = authoritativeOperations.Where(identity => identity.Vocabulary == grant.Vocabulary).ToArray();
        RejectAmbiguousBareIdentifiers(grant.Vocabulary, authoritative);
        foreach (var operation in grant.Operations)
        {
            var matches = authoritative.Count(identity => identity.Matches(grant.Vocabulary, operation));
            if (matches != 1)
                throw new InvalidOperationException("R3 operation is not in the authoritative definition.");
        }
    }

    public static void RejectAmbiguousBareIdentifiers(string vocabulary, IEnumerable<R3OperationIdentity> authoritativeOperations)
    {
        foreach (var group in authoritativeOperations
                     .Where(identity => identity.Vocabulary == vocabulary)
                     .GroupBy(identity => BareIdentifier(identity.Operation), StringComparer.Ordinal)
                     .Where(group => !string.IsNullOrEmpty(group.Key) && group.Count() > 1))
        {
            throw new InvalidOperationException($"R3 operation id '{group.Key}' is ambiguous across authoritative definitions.");
        }
    }

    private static string? BareIdentifier(R3Operation operation) => operation.Id;
}

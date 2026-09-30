using System.Collections.Concurrent;

namespace AAuth.R3;

/// <summary>
/// Which servers may read an R3 document (r3 #r3-document-access-restriction): the Access
/// Server in <c>aud</c> and the Person Server in <c>ps</c> of a resource token that carries
/// the document's <c>r3_uri</c>. <see cref="R3Challenge"/> records both whenever it mints one;
/// call <see cref="EntitleAsync"/> yourself for resource tokens you mint another way.
/// </summary>
public interface IR3DocumentEntitlements
{
    /// <summary>Allow <paramref name="reader"/> to read the document hashed <paramref name="s256"/>.</summary>
    ValueTask EntitleAsync(string s256, string reader, CancellationToken cancellationToken = default);

    /// <summary>Whether <paramref name="reader"/> may read the document hashed <paramref name="s256"/>.</summary>
    ValueTask<bool> IsEntitledAsync(string s256, string reader, CancellationToken cancellationToken = default);
}

/// <summary>In-memory <see cref="IR3DocumentEntitlements"/>; state is lost on restart and not shared across instances.</summary>
public sealed class InMemoryR3DocumentEntitlements : IR3DocumentEntitlements
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, bool>> _readers = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public ValueTask EntitleAsync(string s256, string reader, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(s256);
        ArgumentException.ThrowIfNullOrEmpty(reader);
        _readers.GetOrAdd(s256, _ => new(StringComparer.Ordinal))[reader] = true;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<bool> IsEntitledAsync(string s256, string reader, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_readers.TryGetValue(s256, out var readers) && readers.ContainsKey(reader));
}

using System;
using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Person;

/// <summary>A persisted directed subject enrollment for one person at one resource.</summary>
public sealed record PersonResourceEnrollment(
    string PersonServer,
    AAuthPersonKey PersonKey,
    string Resource,
    string DirectedSubject,
    string SubjectKeyId,
    DateTimeOffset ApprovedAt)
{
    /// <summary>Resource metadata snapshot captured when first approved, if available.</summary>
    public JsonObject? ResourceMetadata { get; init; }
}

/// <summary>
/// Persists first-resource approval and resolves directed subjects back to the
/// PS-internal person key for later auth-token and call-chaining requests.
/// </summary>
public interface IPersonResourceEnrollmentStore
{
    Task<PersonResourceEnrollment?> GetAsync(
        string personServer, AAuthPersonKey personKey, string resource, CancellationToken cancellationToken = default);

    Task<PersonResourceEnrollment?> FindBySubjectAsync(
        string personServer, string resource, string directedSubject, CancellationToken cancellationToken = default);

    Task<bool> RecordAsync(PersonResourceEnrollment enrollment, CancellationToken cancellationToken = default);
}

/// <summary>In-memory enrollment store for development and tests.</summary>
public sealed class InMemoryPersonResourceEnrollmentStore : IPersonResourceEnrollmentStore
{
    private readonly ConcurrentDictionary<(string PersonServer, string PersonKey, string Resource), PersonResourceEnrollment> _byPerson = new();
    private readonly ConcurrentDictionary<(string PersonServer, string Resource, string Subject), PersonResourceEnrollment> _bySubject = new();

    /// <inheritdoc />
    public Task<PersonResourceEnrollment?> GetAsync(
        string personServer, AAuthPersonKey personKey, string resource, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _byPerson.TryGetValue((personServer, personKey.Value, resource), out var enrollment);
        return Task.FromResult(enrollment);
    }

    /// <inheritdoc />
    public Task<PersonResourceEnrollment?> FindBySubjectAsync(
        string personServer, string resource, string directedSubject, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _bySubject.TryGetValue((personServer, resource, directedSubject), out var enrollment);
        return Task.FromResult(enrollment);
    }

    /// <inheritdoc />
    public Task<bool> RecordAsync(PersonResourceEnrollment enrollment, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(enrollment.PersonServer);
        ArgumentException.ThrowIfNullOrWhiteSpace(enrollment.Resource);
        ArgumentException.ThrowIfNullOrWhiteSpace(enrollment.DirectedSubject);
        ArgumentException.ThrowIfNullOrWhiteSpace(enrollment.SubjectKeyId);
        var personKey = (enrollment.PersonServer, enrollment.PersonKey.Value, enrollment.Resource);
        var subjectKey = (enrollment.PersonServer, enrollment.Resource, enrollment.DirectedSubject);
        if (_byPerson.TryGetValue(personKey, out var existingByPerson) && !Same(existingByPerson, enrollment))
        {
            var oldSubjectKey = (existingByPerson.PersonServer, existingByPerson.Resource, existingByPerson.DirectedSubject);
            _bySubject.TryRemove(oldSubjectKey, out _);
            _byPerson[personKey] = enrollment;
        }
        else
        {
            _byPerson.TryAdd(personKey, enrollment);
        }
        var existingBySubject = _bySubject.GetOrAdd(subjectKey, enrollment);
        if (Same(existingBySubject, enrollment)) return Task.FromResult(true);
        _byPerson.TryRemove(personKey, out _);
        return Task.FromResult(false);
    }

    private static bool Same(PersonResourceEnrollment left, PersonResourceEnrollment right)
        => left.PersonKey == right.PersonKey
            && string.Equals(left.DirectedSubject, right.DirectedSubject, StringComparison.Ordinal)
            && string.Equals(left.SubjectKeyId, right.SubjectKeyId, StringComparison.Ordinal);
}

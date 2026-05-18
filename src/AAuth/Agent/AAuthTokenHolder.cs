using System;

namespace AAuth.Agent;

/// <summary>
/// Mutable single-value carrier-token holder shared between an
/// <see cref="HttpSig.AAuthSigningHandler"/> and a <see cref="ChallengeHandler"/>.
/// Lets the challenge handler swap the active carrier token (agent token →
/// auth token) without rebuilding the HttpClient pipeline.
/// </summary>
/// <remarks>
/// Not thread-safe by design. Phase 2 sample agents are single-threaded.
/// If a future phase needs concurrent requests through the same agent
/// pipeline, replace the field with an <see cref="System.Threading.Interlocked"/>
/// or <c>AsyncLocal&lt;T&gt;</c> approach so an in-flight exchange does not
/// race with parallel signed requests.
/// </remarks>
public sealed class AAuthTokenHolder
{
    // volatile gives us release/acquire semantics on the reference write so
    // a parallel reader running on a different thread observes Update()'s
    // value without needing a full memory barrier. Reference writes are
    // atomic on .NET; volatile only adds ordering.
    private volatile string _token;

    /// <summary>Create the holder with an initial token (typically the agent token).</summary>
    public AAuthTokenHolder(string initialToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(initialToken);
        _token = initialToken;
    }

    /// <summary>Return the current carrier token.</summary>
    public string Current => _token;

    /// <summary>Set the carrier token. Subsequent signed requests use this value.</summary>
    public void Update(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        _token = token;
    }
}

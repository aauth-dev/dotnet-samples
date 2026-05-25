using System;
using System.Net.Http;
using AAuth.Crypto;
using AAuth.HttpSig;

namespace AAuth.Server;

/// <summary>
/// Configuration for a resource acting as an agent to access downstream
/// resources (call-chaining / multi-hop delegation).
/// </summary>
public sealed class CallChainingOptions
{
    /// <summary>
    /// The resource's own agent signing key (must have private component).
    /// Used to sign outbound requests to downstream token endpoints.
    /// </summary>
    public required IAAuthKey AgentKey { get; init; }

    /// <summary>
    /// The <see cref="ISignatureKeyProvider"/> that produces the
    /// <c>Signature-Key</c> header for downstream requests (e.g. a
    /// <see cref="JwtSignatureKeyProvider"/> wrapping the resource's
    /// own agent token).
    /// </summary>
    public required ISignatureKeyProvider SignatureKeyProvider { get; init; }

    /// <summary>
    /// Optional factory for creating the signed <see cref="HttpClient"/>
    /// used to call downstream token endpoints. When null, the handler
    /// creates a default client using <see cref="AAuthSigningHandler"/>.
    /// </summary>
    public Func<HttpClient>? HttpClientFactory { get; init; }
}

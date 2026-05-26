using AAuth.Crypto;

namespace SampleApp;

/// <summary>
/// Holds the self-issued agent identity for pages that don't need external AP enrollment.
/// Registered as a singleton in DI — JWT, Deferred, and CallChain pages use this.
/// </summary>
public sealed record SelfIssuedIdentity(AAuthKey Key, string KeyId, string Issuer, string AgentId);

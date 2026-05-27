---
title: "ITokenRefresher Concrete Types — Implementation Plan"
description: Phased plan for adding AgentProviderTokenRefresher and SelfIssuedTokenRefresher to the SDK
ms.date: 2026-05-27
---

## Phase 1: Add `AgentProviderTokenRefresher`

Add the most commonly needed concrete refresher — wraps `AgentProviderClient.RefreshAsync()`.

### Files

| Action | Path |
|--------|------|
| Create | `src/AAuth/Agent/AgentProviderTokenRefresher.cs` |
| Create | `tests/AAuth.Tests/Agent/AgentProviderTokenRefresherTests.cs` |

### Implementation

```csharp
namespace AAuth.Agent;

/// <summary>
/// Built-in <see cref="ITokenRefresher"/> that refreshes agent tokens via an
/// Agent Provider's refresh endpoint. Wraps <see cref="AgentProviderClient"/>.
/// </summary>
public sealed class AgentProviderTokenRefresher : ITokenRefresher
{
    private readonly AgentProviderClient _client;
    private readonly string _refreshEndpoint;

    public AgentProviderTokenRefresher(HttpClient http, IKeyStore keyStore, string refreshEndpoint)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        _client = new AgentProviderClient(http, keyStore);
        _refreshEndpoint = refreshEndpoint;
    }

    public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
        => _client.RefreshAsync(_refreshEndpoint, context.KeyId, cancellationToken);
}
```

### Tests

* Verify it calls `AgentProviderClient.RefreshAsync` with correct endpoint and key ID
* Verify it throws on null/empty constructor args
* Integration: wire into `AAuthClientBuilder.WithTokenRefresh()` and confirm the pipeline works

### Definition of Done

- [x] `AgentProviderTokenRefresher` compiles and is public in `AAuth.Agent`
- [x] Unit tests pass (argument validation, delegation to `AgentProviderClient`)
- [x] Integration test: `AAuthClientBuilder` + `WithTokenRefresh(new AgentProviderTokenRefresher(...))` succeeds
- [x] Existing 556 tests still pass

---

## Phase 2: Add `SelfIssuedTokenRefresher`

For hosted services that self-issue agent tokens without an AP.

### Files

| Action | Path |
|--------|------|
| Create | `src/AAuth/Agent/SelfIssuedTokenRefresher.cs` |
| Create | `tests/AAuth.Tests/Agent/SelfIssuedTokenRefresherTests.cs` |

### Implementation

```csharp
namespace AAuth.Agent;

/// <summary>
/// Built-in <see cref="ITokenRefresher"/> for hosted services that self-issue
/// agent tokens. Builds a fresh JWT on each refresh using <see cref="AgentTokenBuilder"/>.
/// </summary>
public sealed class SelfIssuedTokenRefresher : ITokenRefresher
{
    private readonly IAAuthKey _key;
    private readonly string _issuer;
    private readonly string _subject;
    private readonly string _keyId;
    private readonly string? _personServer;
    private readonly TimeSpan? _lifetime;

    public SelfIssuedTokenRefresher(
        IAAuthKey key,
        string issuer,
        string subject,
        string keyId,
        string? personServer = null,
        TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(subject);
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        _key = key;
        _issuer = issuer;
        _subject = subject;
        _keyId = keyId;
        _personServer = personServer;
        _lifetime = lifetime;
    }

    public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
    {
        var builder = new Tokens.AgentTokenBuilder
        {
            Issuer = _issuer,
            Subject = _subject,
            KeyId = _keyId,
            Key = _key,
            PersonServer = _personServer,
        };
        if (_lifetime is { } lt)
            builder.Lifetime = lt;

        return Task.FromResult(builder.Build());
    }
}
```

### Tests

* Verify produced JWT has correct `iss`, `sub`, `kid` claims
* Verify custom lifetime is honoured
* Verify null `personServer` omits the `ps` claim
* Verify argument validation

### Definition of Done

- [x] `SelfIssuedTokenRefresher` compiles and is public in `AAuth.Agent`
- [x] Unit tests pass (JWT validation, argument checks, lifetime)
- [x] Integration test: `AAuthClientBuilder` + `WithTokenRefresh(new SelfIssuedTokenRefresher(...))` succeeds
- [x] Existing tests still pass

---

## Phase 3: Update Documentation

Replace all sample `ApTokenRefresher` implementations with the SDK type.

### Files to Update

| File | Change |
|------|--------|
| `docs/workflows/ps-asserted-access.md` | Replace `ApTokenRefresher` class with `new AgentProviderTokenRefresher(...)` |
| `docs/workflows/federated-access.md` | Same |
| `docs/reference/dependency-injection.md` | Replace all `ApTokenRefresher` / `AgentProviderRefresher` with SDK type |
| `docs/workflows/ps-asserted-access.md` (Code Example) | Replace self-issue lambda with `new SelfIssuedTokenRefresher(...)` |
| `docs/README.md` | Add both types to the `AAuth.Agent` API table |
| `docs/reference/configuration.md` | Update `TokenRefresher` description |

### Definition of Done

- [x] No doc file defines a sample `ApTokenRefresher` class
- [x] All DI examples use `AgentProviderTokenRefresher` or `SelfIssuedTokenRefresher`
- [x] `docs/README.md` API table includes both new types
- [x] Doc code blocks compile conceptually (correct `using` statements, constructor args)

---

## Phase 4: Update Samples

### Files to Update

| File | Change |
|------|--------|
| `samples/SampleApp/EnrollmentService.cs` | If it has ad-hoc refresh logic, use `AgentProviderTokenRefresher` |
| `samples/AgentConsole/Program.cs` | Replace inline refresh with `AgentProviderTokenRefresher` if applicable |

### Definition of Done

- [x] Samples compile and use SDK types where appropriate
- [x] `dotnet build` passes
- [x] `dotnet test` passes
- [x] AgentConsole runs successfully with all 4 signing modes (hwk, jwks_uri, jwt, jkt-jwt)

---

## Out of Scope

| Item | Reason |
|------|--------|
| Retry/resilience (Polly) in `AgentProviderTokenRefresher` | Consumer responsibility; can wrap `HttpClient` with resilience handler |
| `IHttpClientFactory` overload | Can be added later without breaking; keep constructor simple for v1 |
| Token caching in `SelfIssuedTokenRefresher` | Tokens are cheap to mint; `TokenRefreshHandler` already manages timing |
| `DelegateTokenRefresher` promotion to public | Already usable via `WithTokenRefresh(Func<...>)` — no need to expose |

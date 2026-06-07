# Error Handling

> [Error Codes](https://explorer.aauth.dev/foundations/errors)

## Overview

The AAuth SDK uses structured error codes at every layer: signature verification, token exchange, and consent polling. This page catalogs all error types and shows how to handle them.

## Signature Errors (Resource → Agent)

When a resource rejects a signature, it returns `401` with the `Signature-Error` header.

### SignatureErrorCode

```csharp
namespace AAuth.Errors;

public enum SignatureErrorCode
{
    InvalidRequest,         // Missing required headers (Signature, Signature-Input, Signature-Key)
    InvalidInput,           // Covered components don't match the required set (see required_input)
    InvalidSignature,       // Signature bytes don't verify against key
    UnsupportedAlgorithm,   // Algorithm not supported by this resource
    InvalidKey,             // Key material is malformed or unsupported
    UnknownKey,             // Key not found (jwks_uri: kid not in JWKS)
    InvalidJwt,             // Agent token JWT fails validation
    ExpiredJwt,             // Agent token exp has passed
}
```

### Wire Format

```csharp
using AAuth.Errors;

// Formatting (server-side)
var header = SignatureError.Format(SignatureErrorCode.InvalidSignature);
// → "invalid_signature"

// With details
var header = SignatureError.Format(
    SignatureErrorCode.InvalidInput,
    requiredInput: new[] { "@method", "@authority", "@path" });
// → "invalid_input;required_input=\"@method\" \"@authority\" \"@path\""

// Parsing (agent-side)
if (SignatureError.TryParse(response.Headers["Signature-Error"], out var code))
{
    Console.WriteLine($"Signature rejected: {code}");
}

// Extract the components a resource demands on an invalid_input error
string[] required = SignatureError.ParseRequiredInput(
    response.Headers["Signature-Error"]);
// → ["content-digest"]   (empty array when no required_input is present)
```

### Adaptive Retry on `invalid_input`

When challenge handling is enabled, the agent handles `invalid_input` with a
`required_input` list automatically: it learns the additional covered
components, re-signs the request covering them, and retries once. Learned
components are cached per origin. If `content-digest` is among the required
components, the signing handler computes it (RFC 9530, `sha-256`) from the
request body before re-signing, so the retry succeeds without caller
intervention. See
[Adaptive Signature Components](../signing-modes/overview.md#adaptive-signature-components)
for how to seed components proactively from resource metadata. `ParseRequiredInput`
is exposed for callers implementing this handshake manually.

## Token Errors (PS/AS → Agent)

When a Person Server or Access Server rejects a token exchange request.

### TokenErrorCode

```csharp
namespace AAuth.Errors;

public enum TokenErrorCode
{
    InvalidRequest,         // Malformed request body
    InvalidAgentToken,      // Agent token fails validation
    ExpiredAgentToken,      // Agent token exp has passed
    InvalidResourceToken,   // Resource token fails validation
    ExpiredResourceToken,   // Resource token exp has passed
    InteractionRequired,    // User must approve (deferred consent, non-terminal 202)
    UserUnreachable,        // No channel to the user; agent declared no interaction capability (terminal 400)
    MissionTerminated,      // Mission already terminated (terminal 403 mission_terminated)
    ServerError,            // Internal server error (transient, retryable)
}
```

### TokenErrorResponse

```csharp
public sealed record TokenErrorResponse(TokenErrorCode Error, string? ErrorDescription = null)
{
    public string ErrorCode { get; }  // wire format: "invalid_request", "expired_agent_token", etc.
}
```

The `TokenExchangeClient` throws when it receives an error response from the PS.

When the PS returns a non-success status with a structured AAuth error body
(`{ "error": ..., "error_description": ... }`), the exchange throws a typed
`AAuthTokenExchangeException` carrying the parsed fields. Responses that are not
parseable AAuth error objects fall back to a plain `HttpRequestException`.

```csharp
public sealed class AAuthTokenExchangeException : Exception
{
    public string ErrorCode { get; }          // e.g. "invalid_resource_token"
    public string? ErrorDescription { get; }  // optional human-readable text
    public int StatusCode { get; }            // HTTP status from the token endpoint
    public bool IsTerminal { get; }           // false only for "server_error" (retryable)
}
```

```csharp
try
{
    var authToken = await exchangeClient.ExchangeAsync(personServer, resourceToken);
}
catch (AAuthTokenExchangeException ex)
{
    Console.WriteLine($"Token exchange failed: {ex.ErrorCode} (HTTP {ex.StatusCode})");
    if (!ex.IsTerminal)
    {
        // Transient (server_error) — a later retry may succeed.
    }
}
catch (HttpRequestException ex)
{
    // Transport failure, or a non-success response without a parseable
    // AAuth error body.
    Console.WriteLine($"Transport error: {ex.Message}");
}
```

If you're calling the PS manually, parse the body yourself with
`TokenErrorResponse`:

```csharp
var response = await signedClient.PostAsync(psTokenEndpoint, content);
if (!response.IsSuccessStatusCode)
{
    var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
    Console.WriteLine($"Token exchange failed: {error?.ErrorCode} — {error?.ErrorDescription}");
}
```

### No interaction capability (`user_unreachable`)

Deferred consent assumes the agent can reach the user. When the exchange resolves
to a `202` deferred requirement but the agent declared **no** interaction
capability (no `OnInteractionRequired` callback was supplied), there is no channel
to drive the consent to a verdict, so the SDK does not hang or poll forever — it
raises a **terminal** `AAuthTokenExchangeException` with
`ErrorCode = "user_unreachable"`, `StatusCode = 400`, and `IsTerminal = true`.
Treat it as a configuration signal: supply an interaction callback (interactive
agent) or accept that the request cannot complete unattended.

> **Forward-looking (draft-02).** The PS *emitting* `user_unreachable` on the wire
> is a draft-02 addition; today the SDK classifies the unreachable-user case
> agent-side. The `TokenErrorCode.UserUnreachable` code is already modelled so
> adopters can pattern-match on it now.

## Polling Errors (Deferred Consent)

When polling a pending URL during deferred consent.

### PollingErrorCode

```csharp
namespace AAuth.Errors;

public enum PollingErrorCode
{
    Denied,        // User explicitly denied the request
    Abandoned,     // User navigated away / session expired
    Expired,       // Interaction timed out server-side
    InvalidCode,   // Code doesn't match any pending interaction
    SlowDown,      // Polling too fast — back off
    ServerError,   // Internal server error
}
```

### PollingErrorException

```csharp
public sealed class PollingErrorException : Exception
{
    public PollingErrorCode ErrorCode { get; }
    public int StatusCode { get; }

    // Wire format helpers
    public static string ToWireCode(PollingErrorCode code);       // e.g., "denied"
    public static bool TryParseCode(string? code, out PollingErrorCode result);
}
```

The `DeferredPoller` handles `SlowDown` automatically (backs off). Terminal errors (`Denied`, `Abandoned`, `Expired`) are thrown as `PollingErrorException`.

## Interaction Exceptions

High-level exceptions thrown by `ChallengeHandler` and `TokenExchangeClient`:

```csharp
namespace AAuth.Agent;

// User denied the request at the interaction URL
public sealed class AAuthInteractionDeniedException : Exception { }

// Polling timed out (MaxTotalWait elapsed without resolution)
public sealed class AAuthInteractionTimeoutException : Exception { }
```

### Handling in Application Code

```csharp
try
{
    var response = await client.GetAsync("https://resource.example/data");
    response.EnsureSuccessStatusCode();
}
catch (AAuthInteractionDeniedException)
{
    // User said no — show appropriate UI
    Console.WriteLine("Access denied by user.");
}
catch (AAuthInteractionTimeoutException)
{
    // Timed out waiting — offer to retry
    Console.WriteLine("Approval timed out. Try again?");
}
catch (AAuthVerificationException ex)
{
    // Signature verification failed (server-side)
    Console.WriteLine($"Verification error: {ex.Message}");
}
catch (TokenVerificationException ex)
{
    // Token validation failed
    Console.WriteLine($"Token error: {ex.Message}");
}
```

## Mission Termination

Once a mission is terminated (the user completed it, or the PS revoked it), the PS
refuses governed requests with `403 mission_terminated` (§Mission Status Errors).
The governance clients surface this as a typed exception.

```csharp
namespace AAuth.Errors;

public sealed class AAuthMissionTerminatedException : Exception
{
    public const string ErrorCode = "mission_terminated";
    public string? MissionStatus { get; }   // e.g. "terminated"
}
```

```csharp
try
{
    await session.RecordAuditAsync(new MissionAction("email.send"));
}
catch (AAuthMissionTerminatedException ex)
{
    // The mission is over — stop acting under it and start a new one if needed.
    Console.WriteLine($"Mission terminated ({ex.MissionStatus}).");
}
```

On the PS side, emit the canonical body with
`GovernanceEndpoints.MissionTerminated()` — see
[Mission Governance (Server)](../server/mission-governance.md#terminating-a-mission).

## Clarification Exceptions

A [clarification chat](clarification-chat.md) can end in two terminal ways: the
agent withdraws, or the round limit is reached.

```csharp
namespace AAuth.Agent;

// The agent called ClarificationResponse.Cancel() / ClarificationExchange.CancelAsync()
public sealed class AAuthClarificationCancelledException : Exception { }

// The exchange exceeded MaxRounds (default ClarificationExchange.DefaultMaxRounds = 5)
public sealed class AAuthClarificationLimitException : Exception
{
    public int MaxRounds { get; }
}
```

## Exception Hierarchy

| Exception | Thrown By | Meaning |
|-----------|----------|---------|
| `AAuthVerificationException` | `AAuthVerifier` | Signature bytes invalid |
| `TokenVerificationException` | `TokenVerifier` | JWT fails validation |
| `AAuthTokenExchangeException` | `TokenExchangeClient` / `ChallengeHandler` | PS token endpoint returned a structured error |
| `AAuthInteractionDeniedException` | `DeferredPoller` / `ChallengeHandler` | User denied |
| `AAuthInteractionTimeoutException` | `DeferredPoller` / `ChallengeHandler` | Polling timed out |
| `PollingErrorException` | `DeferredPoller` | PS returned terminal error during polling |
| `AAuthMissionTerminatedException` | `AuditClient` / `InteractionClient` | Mission terminated (`403 mission_terminated`) |
| `AAuthClarificationCancelledException` | `ClarificationExchange` | Agent withdrew during clarification |
| `AAuthClarificationLimitException` | `ClarificationExchange` | Clarification round limit reached |

## Server-Side Error Emission

```csharp
// In middleware or endpoint — set the Signature-Error header
context.Response.Headers[SignatureError.HeaderName] =
    SignatureError.Format(SignatureErrorCode.InvalidSignature);
context.Response.StatusCode = 401;

// Token exchange error response
return Results.Json(
    new { error = "expired_resource_token", error_description = "Resource token has expired" },
    statusCode: 400);
```

## Further Reading

- [Verification Middleware](../server/verification-middleware.md) — automatic Signature-Error emission
- [Deferred Consent](../workflows/deferred-consent.md) — polling lifecycle
- [Configuration Reference](../reference/configuration.md) — timeout and retry settings
- [Mission Governance Clients](mission-governance-clients.md) — where mission/clarification errors arise
- [Clarification Chat](clarification-chat.md) — the clarification exchange

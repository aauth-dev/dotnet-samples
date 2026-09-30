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
    UnsupportedScheme,      // Signature-Key scheme not accepted by this endpoint
    IssuerMissing,          // jwks_uri/jwks carrier names no issuer
    IssuerMismatch,         // Carrier issuer disagrees with the verified identity
    InvalidRequest,         // Malformed information unrelated to signature verification
    InvalidInput,           // Covered components don't match the required set (see required_input)
    InvalidSignature,       // Signature headers missing or malformed, created older than the window, or bytes don't verify
    UnsupportedAlgorithm,   // Algorithm not supported by this resource
    InvalidKey,             // Signature-Key or its key material is malformed or unsupported
    UnknownKey,             // Key not found (jwks_uri: kid not in JWKS)
    InvalidJwt,             // JWT in Signature-Key fails validation
    ExpiredJwt,             // JWT in Signature-Key exp has passed
    RevokedJwt,             // JWT verifies and is unexpired, but its issuer withdrew it
    ClockSkew,              // JWT iat or signature created is ahead of the verifier clock by more than the window
}
```

The `created` window is symmetric: `AAuthVerifier.MaxAge` (60 seconds by default)
bounds both how old and how far ahead `created` may be. A fresh signature from a
sender whose clock runs ahead still fails with `clock_skew`, so wait and resend
rather than re-signing immediately.

### Wire Format

```csharp
using AAuth.Errors;

// Formatting (server-side)
var header = SignatureError.Format(SignatureErrorCode.InvalidSignature);
// → "invalid_signature"

// With details
var detailedHeader = SignatureError.Format(
    SignatureErrorCode.InvalidInput,
    requiredInput: new[] { "@method", "@authority", "@path" });
// → "invalid_input;required_input=\"@method\" \"@authority\" \"@path\""

// Parsing (agent-side)
var receivedHeader = response.Headers.TryGetValues("Signature-Error", out var values)
    ? values.Single() : null;
if (SignatureError.TryParse(receivedHeader, out var code))
{
    Console.WriteLine($"Signature rejected: {code}");
}

// Extract the components a resource demands on an invalid_input error
string[] required = SignatureError.ParseRequiredInput(
    receivedHeader);
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

Error bodies use `Content-Type: application/problem+json`. The `error` string is
required and determines client behavior. The optional `detail` string describes
this occurrence. RFC 9457 members such as `type`, `title`, `status`, and `instance`
may also appear, but clients must not classify AAuth errors by `type`. Signature
failures remain identified by the `Signature-Error` header, not the body.

```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json

{
    "error": "expired_resource_token",
    "detail": "Resource token has expired; obtain a new token and retry."
}
```

### TokenErrorCode

```csharp
namespace AAuth.Errors;

public enum TokenErrorCode
{
    InvalidRequest,         // Malformed request body
    InvalidResourceToken,   // Resource token fails validation
    ExpiredResourceToken,   // Resource token exp has passed
    RevokedResourceToken,   // The issuing resource withdrew it; do not resubmit
    InvalidPresentedToken,  // Presented person/auth token fails validation
    ExpiredPresentedToken,  // Get a fresh person token, then a fresh resource token
    RevokedPresentedToken,  // Get a fresh person token, then a fresh resource token
    InvalidUpstreamToken,   // Call chaining: upstream token fails validation
    ExpiredUpstreamToken,   // Call chaining: caller must re-authorize at the intermediary
    RevokedUpstreamToken,   // Call chaining: terminal for that token
    InvalidSubagentToken,   // Sub-agent token fails validation or names another parent/issuer
    ExpiredSubagentToken,   // Parent obtains a fresh sub-agent token
    RevokedSubagentToken,   // Terminal for that sub-agent token
    ClockSkew,              // A parameter token's iat is too far ahead; wait, don't refresh
    UserUnreachable,        // No channel to the user; agent declared no interaction capability (terminal 403)
    AsUnreachable,          // PS could not get a verifiable auth token from the AS (502; retry later)
    ServerError,            // Internal server error (transient, retryable)
}
```

### TokenErrorResponse

```csharp
public sealed record TokenErrorResponse(TokenErrorCode Error, string? Detail = null)
{
    public string ErrorCode { get; }  // wire format: "invalid_request", "expired_presented_token", etc.
}
```

`TokenExchangeClient` and `AccessServerClient` throw when a token endpoint returns
an error response.

Token-specific codes exist only for tokens carried as request parameters and
follow the pattern `<invalid|expired|revoked>_<parameter>_token`. A parameter
token that was revoked before the first request is a `400`
`revoked_<parameter>_token` (for example `revoked_upstream_token`). The token in
the `Signature-Key` header has no body code: when it fails, the response is
`401` with `Signature-Error`, and a revoked agent, person, or auth token is
reported as `revoked_jwt` (see [Signature Errors](#signature-errors-resource--agent)).
For a revoked auth token, resources also include
`AAuth-Requirement: requirement=person-token` so the agent can recover without
asking a PS or AS to exchange a resource token bound to the revoked auth token.
A request that is already pending reports a revocation while polling instead
(`403 revoked` with `detail` naming the resource, presented, upstream, or
agent dependency; see [Polling Errors](#polling-errors-deferred-consent)).

When the PS returns a non-success status with a structured AAuth error body
(`{ "error": ..., "detail": ... }`), the exchange throws a typed
`AAuthTokenExchangeException` carrying the parsed fields. Responses that are not
parseable AAuth error objects fall back to a plain `HttpRequestException`.

```csharp
public sealed class AAuthTokenExchangeException : Exception
{
    public string ErrorCode { get; }          // e.g. "invalid_resource_token"
    public string? Detail { get; }           // optional human-readable text
    public int StatusCode { get; }            // HTTP status from the token endpoint
    public bool IsTerminal { get; }           // false only for "server_error" (retryable)
}
```

```csharp
try
{
    // The resource token and the person (or auth) token it names.
    var authToken = await exchangeClient.ExchangeAsync(personServer, resourceToken, heldToken);
}
catch (AAuthTokenExchangeException ex)
{
    Console.WriteLine($"Token exchange failed: {ex.ErrorCode} (HTTP {ex.StatusCode})");
    Console.WriteLine(ex.Detail);
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

When calling the PS manually, parse the wire members explicitly.
`TokenErrorResponse` models known error codes; it is not a JSON wire DTO.

```csharp
var response = await signedClient.PostAsync(psTokenEndpoint, content);
if (!response.IsSuccessStatusCode)
{
    var problem = await response.Content.ReadFromJsonAsync<System.Text.Json.Nodes.JsonObject>();
    var error = (string?)problem?["error"];
    var detail = (string?)problem?["detail"];
    Console.WriteLine($"Token exchange failed: {error}: {detail}");
}
```

### No interaction capability (`user_unreachable`)

Deferred consent assumes the agent can reach the user. When the exchange resolves
to a `202` deferred requirement but the agent declared **no** interaction
capability (no `OnInteractionRequired` callback was supplied), there is no channel
to drive the consent to a verdict, so the SDK does not hang or poll forever — it
raises a **terminal** `AAuthTokenExchangeException` with
`ErrorCode = "user_unreachable"`, `StatusCode = 403`, and `IsTerminal = true`.
Treat it as a configuration signal: supply an interaction callback (interactive
agent) or accept that the request cannot complete unattended.

> **Note.** `user_unreachable` is a terminal hard stop — the PS has no channel to
> the user and the agent declared no `interaction` capability. It is distinct from
> `interaction_required`, which is a non-terminal `202` carrying an interaction URL
> the agent can still drive.

## Polling Errors (Deferred Consent)

When polling a pending URL during deferred consent.

### PollingErrorCode

```csharp
namespace AAuth.Errors;

public enum PollingErrorCode
{
    Denied,        // User explicitly denied the request (403)
    Abandoned,     // User navigated away / session expired (403)
    Expired,       // Timed out server-side (408), e.g. a chained request's upstream token expired
    Revoked,       // A token the pending request depends on was revoked (403)
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

Once a mission is terminated (the person accepted completion, the mission expired,
or it was revoked or superseded), the PS refuses governed requests with
`403 mission_terminated` (§Mission Status Errors). A `mission_s256` the PS does
not know, or that belongs to another agent, is `404 mission_not_found` instead.
The governance clients surface termination as a typed exception.

```csharp
namespace AAuth.Errors;

public sealed class AAuthMissionTerminatedException : Exception
{
    public const string ErrorCode = "mission_terminated";
    public string? MissionStatus { get; }       // always "terminated"
    public string? TerminationReason { get; }   // optional, e.g. "expired" or "revoked"
}
```

```csharp
try
{
    await session.RecordAuditAsync(new MissionAction("add_to_calendar"));
}
catch (AAuthMissionTerminatedException ex)
{
    // The mission is over: stop acting under it. An expired mission invites a
    // new proposal; a revoked one does not.
    Console.WriteLine($"Mission terminated ({ex.TerminationReason ?? "no reason given"}).");
}
```

On the PS side, emit the canonical `application/problem+json` body with
`GovernanceEndpoints.MissionTerminated()`, or
`GovernanceEndpoints.MissionTerminated("expired")` to add a
`termination_reason`. The SDK's own endpoints report `expired` when a
mission's `expires_at` has passed and omit the reason otherwise. See
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
| `AAuthMissionTerminatedException` | `MissionClient` / `MissionSession` / `AuditClient` / `InteractionClient` | Mission terminated (`403 mission_terminated`) |
| `AAuthClarificationCancelledException` | `ClarificationExchange` | Agent withdrew during clarification |
| `AAuthClarificationLimitException` | `ClarificationExchange` | Clarification round limit reached |

## Server-Side Error Emission

```csharp
// In middleware or endpoint — set the Signature-Error header
context.Response.Headers[SignatureError.HeaderName] =
    SignatureError.Format(SignatureErrorCode.InvalidSignature);
context.Response.StatusCode = 401;
```

For a token endpoint error, use the shared helper. It preserves headers already
set by the endpoint and emits only errors; success and deferred `202` responses
continue to use their original media types. Endpoint-specific extension members
can be supplied through `extensions`.

```csharp
using AAuth.Server;

return AAuthProblemDetails.Create(
    "expired_resource_token", "Resource token has expired",
    statusCode: 400);
```

## Further Reading

- [Verification Middleware](../server/verification-middleware.md) — automatic Signature-Error emission
- [Deferred Consent](../workflows/deferred-consent.md) — polling lifecycle
- [Configuration Reference](../reference/configuration.md) — timeout and retry settings
- [Mission Governance Clients](mission-governance-clients.md) — where mission/clarification errors arise
- [Clarification Chat](clarification-chat.md) — the clarification exchange

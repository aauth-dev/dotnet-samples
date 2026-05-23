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
    InvalidInput,           // Malformed Signature-Input structured field
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
```

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
    InteractionRequired,    // User must approve (deferred consent)
    ServerError,            // Internal server error
}
```

### TokenErrorResponse

```csharp
public sealed record TokenErrorResponse(TokenErrorCode Error, string? ErrorDescription = null)
{
    public string ErrorCode { get; }  // wire format: "invalid_request", "expired_agent_token", etc.
}
```

The `TokenExchangeClient` throws when it receives an error response from the PS. Check the HTTP status code and parse the body:

```csharp
// If you're calling the PS manually:
var response = await signedClient.PostAsync(psTokenEndpoint, content);
if (!response.IsSuccessStatusCode)
{
    var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
    Console.WriteLine($"Token exchange failed: {error?.ErrorCode} — {error?.ErrorDescription}");
}
```

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

## Exception Hierarchy

| Exception | Thrown By | Meaning |
|-----------|----------|---------|
| `AAuthVerificationException` | `AAuthVerifier` | Signature bytes invalid |
| `TokenVerificationException` | `TokenVerifier` | JWT fails validation |
| `AAuthInteractionDeniedException` | `DeferredPoller` / `ChallengeHandler` | User denied |
| `AAuthInteractionTimeoutException` | `DeferredPoller` / `ChallengeHandler` | Polling timed out |
| `PollingErrorException` | `DeferredPoller` | PS returned terminal error |

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

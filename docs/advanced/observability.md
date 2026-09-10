---
title: Observability
description: Subscribe to AAuth diagnostics without exposing token material.
---

The AAuth SDK provides built-in OpenTelemetry-compatible tracing via `System.Diagnostics` — no external OTel package dependency required.

## Activity Source

All AAuth operations emit traces through a single `ActivitySource`:

```csharp
// Source name: "AAuth"
var source = AAuthDiagnostics.Source;
```

Subscribe to it in your OTel configuration. This external integration template
requires `OpenTelemetry.Extensions.Hosting` and
`OpenTelemetry.Instrumentation.AspNetCore`, which are not repository dependencies
and are not compiled by the snippet harness:

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddSource(AAuthDiagnostics.SourceName) // "AAuth"
        .AddAspNetCoreInstrumentation());
```

## Server-Side Tags

After successful verification, `AAuthVerificationMiddleware` enriches `Activity.Current` with these tags:

| Tag | Description | Example |
|-----|-------------|---------|
| `aauth.scheme` | Signature-Key scheme | `jwt`, `hwk`, `jkt-jwt`, `jwks_uri` |
| `aauth.level` | Verification level | `Identified`, `Authorized`, `Pseudonymous` |
| `aauth.agent` | Agent identifier | `aauth:myapp@ap.example` |
| `aauth.scope` | Granted scopes (space-separated) | `data:read data:write` |
| `aauth.issuer` | Token issuer | `https://ps.example` |
| `aauth.token_type` | JWT type | `aa-agent+jwt`, `aa-auth+jwt` |
| `aauth.issuer_verified` | Whether issuer JWKS was verified | `True` / `False` |

Tags are only set when `Activity.Current` is non-null (i.e., when a listener is subscribed).

## Client-Side Spans

The SDK creates child Activity spans for key operations:

| Span Name | Source | Description |
|-----------|--------|-------------|
| `AAuth.TokenExchange` | `TokenExchangeClient` | Token exchange request to Person Server |
| `AAuth.ChallengeExchange` | `ChallengeHandler` | Full challenge-exchange-retry cycle |
| `AAuth.DeferredPoll` | `TokenExchangeClient` | Deferred polling loop |

## Tag Constants

Use `AAuthDiagnostics` constants for querying traces:

```csharp
string[] tags =
[
    AAuthDiagnostics.TagScheme,
    AAuthDiagnostics.TagLevel,
    AAuthDiagnostics.TagAgent,
    AAuthDiagnostics.TagScope,
    AAuthDiagnostics.TagIssuer,
    AAuthDiagnostics.TagTokenType,
    AAuthDiagnostics.TagIssuerVerified,
];
```

## No External Dependency

The SDK uses only `System.Diagnostics.ActivitySource` and `System.Diagnostics.Activity` from the .NET BCL. No `OpenTelemetry.*` NuGet packages are required. This means:

- Zero overhead when no listener is subscribed (Activities are not created)
- Compatible with any OTel exporter that subscribes to the `"AAuth"` source
- Works with Azure Monitor, Jaeger, Zipkin, OTLP, or custom exporters

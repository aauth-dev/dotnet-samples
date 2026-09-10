---
title: MockAgentProvider
description: Development Agent Provider with signed enrollment and durable key ownership.
---

## Overview

A minimal Agent Provider (AP) sample for development and testing.

> **Sample only — not part of the AAuth SDK.** This project is illustrative wiring built on top of the SDK. Do not depend on its types or HTTP surface in production code.

## What it does

Implements this repository's signed enrollment/refresh profile using the
informational Bootstrap model:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/aauth-agent.json` | GET | AP metadata |
| `/.well-known/jwks.json` | GET | AP's own signing key (for verifying agent token JWTs) |
| `/agents/{agentId}/jwks.json` | GET | Per-agent public key URL for explicit generic `sig=jwks`; AAuth agents use their agent JWT |
| `/enrol` | POST | Signed `hwk` enrollment with `{jwk, ps?}`; returns `{agent_id, agent_token, key_id, jwks_uri}` |
| `/refresh` | POST | JSON `{}` with HWK or naming-JWT HTTP proof; looks up the durable enrollment and returns `{agent_token}` |
| `/agents` | GET | Dev tool — list registered agents |

## Running

```bash
dotnet run --project samples/MockAgentProvider
```

Defaults to `http://localhost:5301` (HTTP) / `https://localhost:5300` (HTTPS).

## Using with AgentConsole

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/pseudonymous \
  --ap http://localhost:5301 \
  --signing-mode hwk \
  --sub "aauth:myagent@ap.example"
```

## Using with GuidedTour

Add to `samples/GuidedTour/appsettings.json`:

```json
{
  "GuidedTour": {
    "AgentProviderUrl": "http://localhost:5301"
  }
}
```

## Configuration

Settings in `appsettings.json`:

| Key | Default | Description |
|-----|---------|-------------|
| `AgentProvider:Issuer` | `http://localhost:5301` | AP issuer claim in tokens |
| `AgentProvider:KeyId` | `ap-key-1` | Key identifier for the AP signing key |
| `AgentProvider:Database` | `~/.aauth/ap-agents.db` | Durable registration database |

## Enrollment Ownership

The AP assigns a stable key-derived identity under its own host. It does not
accept caller-selected names. The optional `agent_id` must equal the ID already
assigned to the signing key. Signed enrollment covers the actual body digest;
the public key in the body must match the HTTP signing key. Same-key retries
retain the identity and kid across restarts. Changed keys or Person Server
bindings return 409; there is no implicit rotation endpoint.

Use `AAuthClientBuilder.Bootstrap(endpoint).WithKey(durableKey)` or
`AgentProviderClient.EnrolWithKeyAsync` with a null requested ID. `--sub` in
AgentConsole names its local enrollment cache, not an AP-authorized identity.
This development admission policy asserts no human identity. Production
deployments must supply their own admission and authorized rotation policy.

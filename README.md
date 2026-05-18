# dotnet-samples

> **Status: Work in Progress** — Phase 1 of the .NET AAuth SDK is functional (Ed25519 keys, agent JWT, RFC 9421 outbound signing). Resource server, CLI tool, and full multi-agent demo are not yet built. See the [implementation plan](.agent/plans/2026-05-13-dotnet-aauth-sdk/implementation-plan.md) for phase status.

AAuth samples and SDK for .NET — demonstrating the [AAuth protocol](https://github.com/dickhardt/AAuth) for agent-to-resource authorization with cryptographic proof-of-possession.

## What is AAuth?

AAuth is a four-party authorization protocol for AI agents. Every HTTP request carries a cryptographic signature — there are no bearer tokens. See the [protocol spec](aauth-spec/draft-hardt-oauth-aauth-protocol.md) for full details.

## Repository Layout

| Path | Description |
|------|-------------|
| `aauth-spec/` | Protocol specifications (draft-01) copied from [dickhardt/AAuth](https://github.com/dickhardt/AAuth) — see [SPEC-VERSION.md](aauth-spec/SPEC-VERSION.md) for provenance |
| `src/AAuth/` | AAuth SDK library (Ed25519 keys, agent JWT, RFC 9421 signing) |
| `samples/AgentConsole/` | Sample console app that signs an HTTP `GET` with an agent token |
| `tests/AAuth.Tests/` | Unit tests for the SDK |
| `tests/AAuth.Conformance/` | Spec-traceable xUnit tests mirroring the AAuth spec section structure |
| `hello-world/` | Minimal .NET 10 console app (placeholder) |
| `.agent/plans/` | Research and planning documents |
| `.github/instructions/` | Copilot/agent workflow instructions |

## Components

- **AAuth core library** (`src/AAuth/`) — *Phase 1 ✓* Ed25519 keys & JWK helpers, `aa-agent+jwt` builder, RFC 9421 outbound signing handler. *Coming:* token verification, JWKS handling, metadata discovery.
- **Agent sample** (`samples/AgentConsole/`) — *Phase 1 ✓* Signs and sends an HTTP `GET`. *Coming:* three-party challenge-response flow.
- **Resource server sample** — *Phase 2* ASP.NET Core minimal API equivalent of [whoami](https://github.com/aauth-dev/whoami).
- **CLI tool** — *Phase 4* Key generation, bootstrap, and authenticated fetch.
- **Full demo** — *Phase 5* Multi-agent orchestration equivalent of [aauth-full-demo](https://github.com/christian-posta/aauth-full-demo).

See [research.md](.agent/plans/2026-05-13-dotnet-aauth-sdk/research.md) for the full research document and implementation plan.

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/products/docker-desktop)
- [Visual Studio Code](https://code.visualstudio.com/) with the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

### Using the Dev Container

1. Clone this repository.
2. Open the repository in Visual Studio Code.
3. When prompted, click **Reopen in Container** (or run the **Dev Containers: Reopen in Container** command from the Command Palette).
4. VS Code will build the Docker image defined in `.devcontainer/Dockerfile` using the .NET 10 SDK and open the project inside the container.

## Samples

### Agent Console (`samples/AgentConsole/`)

Generates (or loads) an Ed25519 key, builds an `aa-agent+jwt`, and sends a signed `GET` request. Inspect the echoed `Signature`, `Signature-Input`, and `Signature-Key` headers to see RFC 9421 in action.

```bash
dotnet run --project samples/AgentConsole -- https://httpbin.org/get
```

Optional flags: `--iss <url>` (agent issuer), `--sub <id>` (subject), `--kid <name>` (key id under `~/.aauth/keys/`).

### Hello World (`hello-world/`)

A minimal "Hello, World!" console application targeting .NET 10.

```bash
cd hello-world
dotnet run
```

## Building and Testing

```bash
dotnet build AAuth.slnx
dotnet test  AAuth.slnx
```

The conformance suite (`tests/AAuth.Conformance/`) renders as a section-by-section checklist against the spec — see [tests/AAuth.Conformance/README.md](tests/AAuth.Conformance/README.md) for the section→file map.

## Dev Container Details

The dev container is configured in `.devcontainer/`:

| File | Description |
|------|-------------|
| `Dockerfile` | Builds an image based on `mcr.microsoft.com/dotnet/sdk:10.0` |
| `devcontainer.json` | Configures VS Code extensions and the post-create command |
| `post-create.sh` | Runs on container create: prints `dotnet --info` and installs the GitHub CLI (`gh`) |

Included VS Code extensions:
- **C# Dev Kit** (`ms-dotnettools.csdevkit`)
- **C#** (`ms-dotnettools.csharp`)
- **.NET Runtime Install Tool** (`ms-dotnettools.vscode-dotnet-runtime`)

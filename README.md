# dotnet-samples

> **Status: Work in Progress** — This repo is under active development. The .NET AAuth SDK and samples are not yet functional.

AAuth samples and SDK for .NET — demonstrating the [AAuth protocol](https://github.com/dickhardt/AAuth) for agent-to-resource authorization with cryptographic proof-of-possession.

## What is AAuth?

AAuth is a four-party authorization protocol for AI agents. Every HTTP request carries a cryptographic signature — there are no bearer tokens. See the [protocol spec](aauth-spec/draft-hardt-oauth-aauth-protocol.md) for full details.

## Repository Layout

| Path | Description |
|------|-------------|
| `aauth-spec/` | Protocol specifications (draft-01) copied from [dickhardt/AAuth](https://github.com/dickhardt/AAuth) — see [SPEC-VERSION.md](aauth-spec/SPEC-VERSION.md) for provenance |
| `hello-world/` | Minimal .NET 10 console app (placeholder) |
| `.agent/plans/` | Research and planning documents |

## Planned Components

- **AAuth core library** — RFC 9421 HTTP signatures, JWT token creation/verification, JWK/JWKS handling, metadata discovery
- **Agent sample** — Console app that signs requests and handles the three-party challenge-response flow
- **Resource server sample** — ASP.NET Core minimal API equivalent of [whoami](https://github.com/aauth-dev/whoami)
- **CLI tool** — Key generation, bootstrap, and authenticated fetch
- **Full demo** — Multi-agent orchestration equivalent of [aauth-full-demo](https://github.com/christian-posta/aauth-full-demo)

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

### Hello World (`hello-world/`)

A minimal "Hello, World!" console application targeting .NET 10.

```bash
cd hello-world
dotnet run
```

## Dev Container Details

The dev container is configured in `.devcontainer/`:

| File | Description |
|------|-------------|
| `Dockerfile` | Builds an image based on `mcr.microsoft.com/dotnet/sdk:10.0` |
| `devcontainer.json` | Configures VS Code extensions and the post-create restore command |

Included VS Code extensions:
- **C# Dev Kit** (`ms-dotnettools.csdevkit`)
- **C#** (`ms-dotnettools.csharp`)
- **.NET Runtime Install Tool** (`ms-dotnettools.vscode-dotnet-runtime`)

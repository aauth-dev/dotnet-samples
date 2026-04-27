# dotnet-samples

AAuth samples in .NET

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

**Run the sample:**

```bash
cd hello-world
dotnet run
```

Expected output:

```
Hello, World!
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

#!/usr/bin/env bash
# Post-create script for the AAuth .NET dev container.
# Idempotent: safe to re-run.

set -euo pipefail

echo "==> dotnet --info"
dotnet --info

# --- GitHub CLI ---------------------------------------------------------------
# Installs `gh` from the official GitHub apt repository.
# Docs: https://github.com/cli/cli/blob/trunk/docs/install_linux.md
if ! command -v gh >/dev/null 2>&1; then
    echo "==> Installing GitHub CLI (gh)"

    sudo_cmd=""
    if [[ $EUID -ne 0 ]]; then
        sudo_cmd="sudo"
    fi

    $sudo_cmd install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | $sudo_cmd tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
    $sudo_cmd chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg

    arch=$(dpkg --print-architecture)
    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        | $sudo_cmd tee /etc/apt/sources.list.d/github-cli.list >/dev/null

    $sudo_cmd apt-get update
    $sudo_cmd apt-get install -y gh
else
    echo "==> gh already installed: $(gh --version | head -n1)"
fi

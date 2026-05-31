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

# --- cloudflared --------------------------------------------------------------
# Installs `cloudflared` from Cloudflare's official apt repository.
# Required by the LiveWhoAmITest sample, which exposes its local agent metadata
# endpoint over a quick tunnel so the live resource server can fetch its JWKS.
# Docs: https://pkg.cloudflare.com/
if ! command -v cloudflared >/dev/null 2>&1; then
    echo "==> Installing cloudflared"

    sudo_cmd=""
    if [[ $EUID -ne 0 ]]; then
        sudo_cmd="sudo"
    fi

    $sudo_cmd install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
        | $sudo_cmd tee /etc/apt/keyrings/cloudflare-main.gpg >/dev/null
    $sudo_cmd chmod go+r /etc/apt/keyrings/cloudflare-main.gpg

    echo "deb [signed-by=/etc/apt/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
        | $sudo_cmd tee /etc/apt/sources.list.d/cloudflared.list >/dev/null

    $sudo_cmd apt-get update
    $sudo_cmd apt-get install -y cloudflared
else
    echo "==> cloudflared already installed: $(cloudflared --version | head -n1)"
fi

# --- Node.js (for Playwright E2E tests) ---------------------------------------
# Installs Node.js 20 LTS from NodeSource. The browser end-to-end suite under
# tests/e2e/ uses @playwright/test (TypeScript), which needs a Node toolchain.
# Docs: https://github.com/nodesource/distributions
if ! command -v node >/dev/null 2>&1; then
    echo "==> Installing Node.js 20 LTS"

    sudo_cmd=""
    if [[ $EUID -ne 0 ]]; then
        sudo_cmd="sudo"
    fi

    curl -fsSL https://deb.nodesource.com/setup_20.x | $sudo_cmd bash -
    $sudo_cmd apt-get install -y nodejs
else
    echo "==> Node.js already installed: $(node --version)"
fi

# --- Playwright E2E dependencies + browsers ------------------------------------
# Installs the npm toolchain and the Chromium browser used by the E2E suite.
# Idempotent: npm ci is a no-op when node_modules is current; browser install
# skips already-present binaries.
E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/e2e"
if [[ -f "${E2E_DIR}/package.json" ]]; then
    echo "==> Installing Playwright E2E toolchain in ${E2E_DIR}"
    (cd "${E2E_DIR}" && npm ci && npx --yes playwright install --with-deps chromium)
else
    echo "==> Skipping Playwright install (no ${E2E_DIR}/package.json yet)"
fi

# --- Bash: git completion + git status in prompt ------------------------------

# Idempotent: only appended once, guarded by a marker line.
BASHRC="${HOME}/.bashrc"
MARKER="# >>> aauth devcontainer bash setup >>>"
if ! grep -qF "${MARKER}" "${BASHRC}" 2>/dev/null; then
    echo "==> Configuring bash completion and git-aware prompt in ${BASHRC}"
    cat >> "${BASHRC}" <<'EOF'

# >>> aauth devcontainer bash setup >>>
# Enable bash completion (provides git tab-completion among others)
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
fi

# Git branch/status in prompt via __git_ps1
if [ -f /usr/share/git-core/contrib/completion/git-prompt.sh ]; then
    . /usr/share/git-core/contrib/completion/git-prompt.sh
    GIT_PS1_SHOWDIRTYSTATE=1
    GIT_PS1_SHOWUNTRACKEDFILES=1
    GIT_PS1_SHOWUPSTREAM="auto"
    PS1='\[\e[32m\]\u@\h\[\e[0m\]:\[\e[34m\]\w\[\e[33m\]$(__git_ps1 " (%s)")\[\e[0m\]\$ '
fi
# <<< aauth devcontainer bash setup <<<
EOF
else
    echo "==> bash setup already present in ${BASHRC}"
fi

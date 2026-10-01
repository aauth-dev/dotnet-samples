import { defineConfig, devices } from '@playwright/test';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Playwright config for the AAuth Blazor demo E2E suite.
 *
 * Two projects map to the two demo apps. Their spec files live *inside* the
 * sample folders (`samples/<App>/playwright-tests/`) while this config and the
 * Node toolchain live once under `tests/e2e/`.
 *
 * The `webServer` array boots every backend the demos need, plus both apps.
 * `reuseExistingServer` lets a developer who already ran `make demo`
 * reuse those processes; CI / a clean run boots fresh.
 *
 * MockPersonServer MUST run with RequireConsent=true so the deferred /
 * user-consent paths fire.
 */

const repoRoot = '../..';

// Demo servers persist keys and databases under $HOME/.aauth. Give them a scratch
// HOME (fresh per run; set AAUTH_E2E_HOME to keep one) so a developer's own
// ~/.aauth never leaks into a run. Worker processes re-read this file, so only
// the main process resets it.
const realHome = os.homedir();
const stateHome = process.env.AAUTH_E2E_HOME ?? path.join(os.tmpdir(), 'aauth-e2e-home');
if (!process.env.AAUTH_E2E_HOME && !process.env.TEST_WORKER_INDEX) {
  fs.rmSync(stateHome, { recursive: true, force: true });
}
fs.mkdirSync(path.join(stateHome, '.local', 'share'), { recursive: true });
const stateEnv = {
  HOME: stateHome,
  XDG_DATA_HOME: path.join(stateHome, '.local', 'share'),
  NUGET_PACKAGES: process.env.NUGET_PACKAGES ?? path.join(realHome, '.nuget', 'packages'),
  DOTNET_CLI_HOME: process.env.DOTNET_CLI_HOME ?? realHome,
};

function dotnetRun(project: string, env?: Record<string, string>) {
  return {
    command: `dotnet run --project ${project}`,
    cwd: repoRoot,
    env: { AAuth__EnableIsolatedDemoConsent: 'true', ...stateEnv, ...env },
    reuseExistingServer: !process.env.CI,
    stdout: 'pipe' as const,
    stderr: 'pipe' as const,
    timeout: 180_000,
  };
}

export default defineConfig({
  testDir: '.',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['html', { open: 'never' }], ['list']],

  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'guided-tour',
      testDir: `${repoRoot}/samples/GuidedTour/playwright-tests`,
      use: { ...devices['Desktop Chrome'], baseURL: 'http://localhost:5400' },
    },
    {
      name: 'sample-app',
      testDir: `${repoRoot}/samples/SampleApp/playwright-tests`,
      use: { ...devices['Desktop Chrome'], baseURL: 'http://localhost:5240' },
    },
  ],

  webServer: [
    {
      ...dotnetRun('samples/MockResourceServers/Documents/Documents.csproj'),
      url: 'http://localhost:5007/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/MockResourceServers/Catalog/Catalog.csproj'),
      url: 'http://localhost:5006/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/MockResourceServers/Profile/Profile.csproj'),
      url: 'http://localhost:5000/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/MockResourceServers/Calendar/Calendar.csproj'),
      url: 'http://localhost:5001/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/MockResourceServers/Trips/Trips.csproj'),
      url: 'http://localhost:5002/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/MockResourceServers/Wallet/Wallet.csproj'),
      url: 'http://localhost:5003/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/MockResourceServers/Inbox/Inbox.csproj'),
      url: 'http://localhost:5004/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/Concierge/Concierge.csproj'),
      url: 'http://localhost:5200/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/MockAgentProvider/MockAgentProvider.csproj'),
      url: 'http://localhost:5301/.well-known/aauth-agent.json',
    },
    {
      ...dotnetRun('samples/MockPersonServer/MockPersonServer.csproj', {
        MockPersonServer__RequireConsent: 'true',
        // Federate to both the Federated AS (Wallet) and the R3 AS (Bookings).
        MockPersonServer__TrustedAccessServers__0: 'http://localhost:5500',
        MockPersonServer__TrustedAccessServers__1: 'http://localhost:5501',
      }),
      url: 'http://localhost:5100/.well-known/aauth-person.json',
    },
    {
      // Access Server for the four-party (federated) specs. Defaults to the
      // pure-.NET stub policy (no Docker / Keycloak) so the suite runs in CI.
      // RequireConsent makes the stub return 202 + its own consent screen, so
      // the federated flow is interactive (user clicks Approve) just like the
      // deferred flow — from the agent's perspective the stub and Keycloak are
      // identical. Set AccessServer__PolicyProvider=keycloak (and the
      // Keycloak__* vars) plus KEYCLOAK_E2E=1 to exercise the Keycloak path.
      ...dotnetRun('samples/MockAccessServers/Federated/Federated.csproj', {
        AccessServer__PolicyProvider: process.env.AccessServer__PolicyProvider ?? 'stub',
        AccessServer__RequireConsent: process.env.AccessServer__RequireConsent ?? 'true',
      }),
      url: 'http://localhost:5500/.well-known/aauth-access.json',
    },
    {
      // Bookings (R3) resource server for the Rich Resource Requests specs.
      ...dotnetRun('samples/MockResourceServers/Bookings/Bookings.csproj'),
      url: 'http://localhost:5005/.well-known/aauth-resource.json',
    },
    {
      // Dedicated R3 Access Server guarding Bookings and the Travel Catalog.
      ...dotnetRun('samples/MockAccessServers/R3/R3.csproj'),
      url: 'http://localhost:5501/.well-known/aauth-access.json',
    },
    {
      ...dotnetRun('samples/GuidedTour/GuidedTour.csproj'),
      url: 'http://localhost:5400',
    },
    {
      ...dotnetRun('samples/SampleApp/SampleApp.csproj'),
      url: 'http://localhost:5240',
    },
  ],
});

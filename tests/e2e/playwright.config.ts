import { defineConfig, devices } from '@playwright/test';

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

function dotnetRun(project: string, env?: Record<string, string>) {
  return {
    command: `dotnet run --project ${project}`,
    cwd: repoRoot,
    env,
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
      ...dotnetRun('samples/MockResourceServers/Bookings/Bookings.csproj'),
      url: 'http://localhost:5005/.well-known/aauth-resource.json',
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
      ...dotnetRun('samples/MockAccessServer/MockAccessServer.csproj', {
        AccessServer__PolicyProvider: process.env.AccessServer__PolicyProvider ?? 'stub',
        AccessServer__RequireConsent: process.env.AccessServer__RequireConsent ?? 'true',
      }),
      url: 'http://localhost:5500/.well-known/aauth-access.json',
    },
    {
      // Dedicated Access Server for the experimental R3 Bookings flow. The
      // server selects R3 mode by configuration so the shared :5500 AS used by
      // Wallet/federated specs remains untouched.
      ...dotnetRun('samples/MockAccessServer/MockAccessServer.csproj --launch-profile MockAccessServer.R3'),
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

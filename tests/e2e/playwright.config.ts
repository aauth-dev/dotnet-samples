import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for the AAuth Blazor demo E2E suite.
 *
 * Two projects map to the two demo apps. Their spec files live *inside* the
 * sample folders (`samples/<App>/playwright-tests/`) while this config and the
 * Node toolchain live once under `tests/e2e/`.
 *
 * The `webServer` array boots every backend the demos need, plus both apps.
 * `reuseExistingServer` lets a developer who already ran `make demo` /
 * `make demo-sample` reuse those processes; CI / a clean run boots fresh.
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
      ...dotnetRun('samples/WhoAmI/WhoAmI.csproj'),
      url: 'http://localhost:5000/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/Orchestrator/Orchestrator.csproj'),
      url: 'http://localhost:5200/.well-known/aauth-resource.json',
    },
    {
      ...dotnetRun('samples/MockAgentProvider/MockAgentProvider.csproj'),
      url: 'http://localhost:5301/.well-known/aauth-agent.json',
    },
    {
      ...dotnetRun('samples/MockPersonServer/MockPersonServer.csproj', {
        MockPersonServer__RequireConsent: 'true',
      }),
      url: 'http://localhost:5100/.well-known/aauth-person.json',
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

/**
 * Known identifiers and URLs shared by the E2E specs.
 *
 * Mirrors the demo `appsettings.json` values for SampleApp and GuidedTour and
 * the ports declared in the repo `Makefile`. Keep in sync if those change.
 */
export const Urls = {
  profile: 'http://localhost:5000',
  calendar: 'http://localhost:5001',
  trips: 'http://localhost:5002',
  wallet: 'http://localhost:5003',
  personServer: 'http://localhost:5100',
  concierge: 'http://localhost:5200',
  agentProvider: 'http://localhost:5301',
  accessServer: 'http://localhost:5500',
} as const;

export const Agents = {
  /** SampleApp's self-issued agent id (SampleApp/appsettings.json). */
  sampleApp: 'aauth:sample-app@localhost:5240',
  /** GuidedTour agent id (GuidedTour/appsettings.json). */
  tour: 'aauth:tour-agent@localhost:5400',
} as const;

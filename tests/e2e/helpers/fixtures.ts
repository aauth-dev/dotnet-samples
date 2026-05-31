import { test as base, expect } from '@playwright/test';
import { resetConsent } from './consent';

/**
 * Shared test object for the whole E2E suite.
 *
 * It adds one auto-fixture, `consentReset`, that wipes the MockPersonServer's
 * consent + pending state back to an empty baseline before every test. Because
 * fixture setup runs before any `test.beforeEach` hook, specs that seed their
 * own standing consent (via grantConsent) still start from a clean slate, and
 * specs run independently of order — a grant in one spec can no longer leak
 * into another. The GuidedTour re-seeds its own consent on page load / flow
 * selection, so the reset is harmless there too.
 *
 * Every spec must import `test` and `expect` from this module instead of
 * '@playwright/test' so the auto-fixture is applied.
 */
export const test = base.extend<{ consentReset: void }>({
  consentReset: [
    async ({ request }, use) => {
      await resetConsent(request);
      await use();
    },
    { auto: true },
  ],
});

export { expect };

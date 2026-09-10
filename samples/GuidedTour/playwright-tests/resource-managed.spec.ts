import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { authenticateConsent } from '../../../tests/e2e/helpers/consent';
import {
  openTour,
  selectFlow,
  runAll,
  selectStep,
  expectResponse,
  readResponseJson,
  doneSteps,
  TourMode,
} from '../../../tests/e2e/helpers/tour';

/**
 * Resource-Managed (Guided Tour) — two-party AAuth-Access flow, 6 steps. The
 * Inbox manages authorization itself: the signed GET /messages returns 202 with
 * an interaction requirement pointing at the Inbox's OWN consent page (no Person
 * Server). "Run all" parks on the user-approval step and surfaces the consent
 * link; the user approves in a new tab at the Inbox while the agent polls the
 * pending URL. On approval the Inbox issues an opaque AAuth-Access token the SDK
 * replays — bound to the signature — to read the inbox.
 *
 * Mirrors the Deferred flow, but every leg is Agent ↔ Inbox (no PS, no token
 * exchange). Approval happens at the Inbox consent page (#approve), not the PS.
 */
test.describe('Resource-Managed (Guided Tour)', () => {
  test.describe.configure({ timeout: 120_000 });

  test('approve at the Inbox resolves to a two-party 200 with messages', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.ResourceManaged);
    await expect(page.locator('.flow-picker__desc')).toContainText('locally self-issues');
    await expect(page.locator('.flow-picker__desc')).toContainText('No external AP enrollment');
    await expect(page.locator('.config')).toContainText('Agent issuer (self-issued):');
    await expect(page.locator('.config')).toContainText('http://localhost:5400');
    await expect(page.locator('.config')).not.toContainText('http://localhost:5301');
    await expect(page.locator('.config')).not.toContainText('Person Server:');

    await runAll(page);

    // Parked on the user-approval step: the Inbox consent link is shown.
    const link = page.locator('a.primary.approve');
    await expect(link).toBeVisible();

    // Opening the link starts the background poll loop and opens the Inbox
    // consent page in a new tab.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await authenticateConsent(popup);
    await popup.locator('#approve').click();
    await popup.getByText('Approved', { exact: false }).first().waitFor();

    // The poll loop captures the issued AAuth-Access (step 5 of 6). The final
    // replay step (6) still needs an explicit run once polling ends.
    await expect(doneSteps(page)).toHaveCount(5, { timeout: 90_000 });
    const primary = page.locator('button.primary');
    await expect(primary).toBeEnabled();
    await primary.click();

    await expect(doneSteps(page)).toHaveCount(6, { timeout: 30_000 });

    await selectStep(page, 1);
    await expect(page.locator('body')).toContainText('Setup: GuidedTour acts as its own AP');
    await expect(page.locator('body')).toContainText('AAuthClientBuilder.SelfIssuing');

    // Step 6 ("Replay GET /messages with AAuth-Access") is the resource result.
    await selectStep(page, 5);
    await expectResponse(page, 200, ['inbox.read']);

    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.scope).toBe('inbox.read');
    expect(Array.isArray(json.messages)).toBe(true);
    await page.screenshot({ path: test.info().outputPath('inbox-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    const pickerBounds = await page.locator('.flow-picker').boundingBox();
    const selectorBounds = await page.locator('#flow-select').boundingBox();
    expect(selectorBounds!.x + selectorBounds!.width).toBeLessThanOrEqual(pickerBounds!.x + pickerBounds!.width);
    const layoutBounds = await page.locator('.layout').boundingBox();
    expect(layoutBounds!.y).toBeGreaterThanOrEqual(pickerBounds!.y + pickerBounds!.height);
    await page.locator('.payload').scrollIntoViewIfNeeded();
    await expect(page.locator('.payload')).toBeInViewport();
    await page.screenshot({ path: test.info().outputPath('inbox-mobile.png'), fullPage: true });
  });
});

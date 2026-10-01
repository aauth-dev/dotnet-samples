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
 * Server). "Run all" records the user-decision step, starts polling at once and
 * shows the consent link; the user approves in a new tab at the Inbox and "Run
 * all" carries on. On approval the Inbox issues an opaque AAuth-Access token the
 * SDK replays — bound to the signature — to read the inbox.
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

    // The decision step (4) is recorded and the agent is already polling; the
    // banner shows the Inbox consent link.
    const link = page.locator('section.polling a.primary.approve');
    await expect(link).toBeVisible();
    await expect(link).toHaveText('Open Inbox consent page');
    await expect(doneSteps(page)).toHaveCount(4);
    await expect(page.locator('section.polling .polling__detail')).toContainText(/[1-9]\d* polls? so far/, { timeout: 15_000 });

    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await authenticateConsent(popup);
    await popup.locator('#approve').click();
    await popup.getByText('Approved', { exact: false }).first().waitFor();

    // The poll captures the issued AAuth-Access (step 5) and "Run all" replays
    // with it (step 6) without another click.
    await expect(doneSteps(page)).toHaveCount(6, { timeout: 90_000 });
    await expect(page.locator('button.primary')).toHaveText('Done');
    await expect(page.locator('header.topbar .error')).toHaveCount(0);

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

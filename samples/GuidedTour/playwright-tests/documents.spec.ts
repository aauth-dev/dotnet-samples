import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour, selectFlow, driveTour, decideConsent, doneTitles, selectStepTitled,
  expectResponse, readResponseJson, decodedTokenPayload, TourMode,
} from '../../../tests/e2e/helpers/tour';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';

/**
 * Document Release (flow 14) in the standard tour: the person-token leg, a
 * verified resource token naming the owner's permission page, a 202 exchange,
 * the owner's release then PS consent in one browser decision, the poll, and
 * the download. Declining at the owner aborts with no document released.
 */
test.describe('Document Release (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('owner release precedes PS consent and the document is downloaded', async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Documents);
    await expect(page.locator('.lanes .lane')).toHaveText(['Agent', 'Documents', 'Person Server']);

    const decisions = await driveTour(page, (popup) => decideConsent(popup, true));
    expect(decisions).toBe(1);
    await expect(page.locator('button.primary')).toHaveText('Done');
    const titles = await doneTitles(page);
    expect(titles).toHaveLength(11);
    expect(titles[6]).toBe('POST /token → 202 interaction');
    expect(titles[8]).toBe('User decides at the Documents owner, then the Person Server');

    await selectStepTitled(page, /with person token → 401 \+ resource token/);
    const resourceToken = await decodedTokenPayload(page);
    expect(resourceToken.account).toBe('work');
    expect((resourceToken.interaction as { url: string }).url).toBe('http://localhost:5007/permission');

    await selectStepTitled(page, /^Poll Person Server pending URL|^Poll pending URL/);
    await expectResponse(page, 200, ['auth_token']);
    const auth = await decodedTokenPayload(page);
    expect(auth.ps).toBe(resourceToken.ps);
    expect(auth.sub).toBe(resourceToken.sub);
    expect(auth.account).toBe('work');
    expect(auth).not.toHaveProperty('agent');

    await selectStepTitled(page, /released$/);
    await expectResponse(page, 200);
    expect(((await readResponseJson(page)) as { released: boolean }).released).toBe(true);
    // The diagram draws the poll inside a completed loop box.
    await expect(page.locator('.seq-loop.completed.ok')).toHaveCount(1);
  });

  test('declining at the document owner aborts without releasing', async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Documents);
    await driveTour(page, (popup) => decideConsent(popup, false));
    await expect(page.locator('button.primary')).toHaveText('Aborted');
    const titles = await doneTitles(page);
    expect(titles[titles.length - 1]).toMatch(/403 denied/);
    expect(titles.some((title) => title.includes('released'))).toBe(false);
  });

  test('the old /documents route opens the flow in the tour', async ({ page }) => {
    await page.goto('/documents');
    await expect(page).toHaveURL(/\/tour\?flow=Documents$/);
    await waitForInteractive(page, 'button.primary');
    await expect(page.locator('select#flow-select')).toHaveValue('Documents');
  });
});

import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour, selectFlow, driveTour, decideConsent, doneTitles, selectStepTitled,
  expectResponse, readResponseJson, decodedTokenPayload, TourMode,
} from '../../../tests/e2e/helpers/tour';
import { Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Travel Catalog (flow 15) in the standard tour: the merged OpenAPI definition,
 * an operation-bound R3 grant from the R3 Access Server, the sibling operation
 * rejecting that grant, and recovery with a grant for the sibling.
 */
test.describe('Travel Catalog (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  for (const service of ['destinations', 'experiences'] as const) {
    test(`${service} grant cannot read its sibling until it is authorized`, async ({ page }) => {
      const sibling = service === 'destinations' ? 'experiences' : 'destinations';
      const operation = (name: string) => 'list' + name[0].toUpperCase() + name.slice(1);
      await openTour(page);
      await selectFlow(page, TourMode.Catalog);
      await expect(page.locator('.lanes .lane')).toHaveText(['Agent', 'Catalog', 'Person Server', 'R3 Access Server']);
      const picker = page.locator('select#catalog-service-select');
      await expect(async () => {
        await picker.selectOption(service);
        await expect(page.locator('aside.steps .step').nth(2)).toContainText(`/catalog/${service}`, { timeout: 2_000 });
      }).toPass({ timeout: 20_000 });

      await driveTour(page, (popup) => decideConsent(popup, true));
      await expect(page.locator('button.primary')).toHaveText('Done');
      const titles = await doneTitles(page);
      expect(titles.length).toBeGreaterThanOrEqual(13);

      await selectStepTitled(page, /merged OpenAPI definition/);
      await expectResponse(page, 200, ['listDestinations', 'listExperiences']);

      await selectStepTitled(page, /Parse the R3 resource token/);
      const resourceToken = await decodedTokenPayload(page);
      expect(resourceToken.aud).toBe(Urls.r3AccessServer);
      expect(resourceToken.r3_uri).toBeTruthy();

      await selectStepTitled(page, new RegExp(`GET /catalog/${service} with auth token → 200`));
      await expectResponse(page, 200);
      expect(((await readResponseJson(page)) as { operationId: string }).operationId).toBe(operation(service));

      await selectStepTitled(page, new RegExp(`GET /catalog/${sibling} with the same grant → 403`));
      await expectResponse(page, 403);

      await selectStepTitled(page, new RegExp(`GET /catalog/${sibling} with fresh grant → 200`));
      await expectResponse(page, 200);
      expect(((await readResponseJson(page)) as { operationId: string }).operationId).toBe(operation(sibling));
    });
  }
});

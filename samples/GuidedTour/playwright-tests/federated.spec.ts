import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour,
  selectFlow,
  runAll,
  selectStep,
  expectResponse,
  readResponseJson,
  TourMode,
} from '../../../tests/e2e/helpers/tour';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Federated (four-party) — Guided Tour, direct-grant path.
 *
 * Exercises the four-party swimlane flow against a **stub** Access Server
 * policy (auto-approve, no Keycloak / Docker). The resource's /federated branch
 * challenges with a resource_token whose `aud` is the Access Server; the PS
 * federates to the AS, which mints the `aa-auth+jwt`. The replay step resolves
 * to a four-party 200 issued by the Access Server.
 *
 * The interactive Keycloak consent path (202 → login → poll) is covered by the
 * SampleApp `federated-deferred.spec.ts` (gated on KEYCLOAK_E2E=1).
 */
test.describe('Federated (Guided Tour)', () => {
  test.describe.configure({ timeout: 90_000 });

  test('renders four swimlanes and resolves to a four-party 200', async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Federated);

    // The four-party flow shows a distinct Access Server lane (rendered red).
    await expect(page.locator('.lanes .lane.agent')).toContainText('Agent');
    await expect(page.locator('.lanes .lane.ps')).toContainText('Person Server');
    await expect(page.locator('.lanes .lane.as')).toContainText('Access Server');

    await runAll(page);

    // Step 6 ("Replay GET /federated with auth_token → 200") holds the result.
    await selectStep(page, 5);
    await expectResponse(page, 200, ['four-party']);

    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.mode).toBe('four-party');
    expect(json.scheme).toBe('jwt');
    expect(json.agent).toBe(Agents.tour);
    expect(json.scope).toEqual(['whoami']);
    // The auth token is issued by the Access Server, not the Person Server.
    expect(json.iss).toBe(Urls.accessServer);
    const act = json.act as Record<string, unknown>;
    expect(act.sub).toBe(Agents.tour);
  });
});

import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { openTour, selectFlow, runAll, doneSteps, selectStep, TourMode } from '../../../tests/e2e/helpers/tour';

/**
 * Sub-Agents — parent-mediated workers, 8 steps. Unlike the protocol flows this
 * one runs the token lifecycle entirely IN-PROCESS with the real SDK builders
 * (no live servers), so the DoD asserts the wire artifacts the steps surface:
 * the sub-agent's `parent_agent` claim (step 2), the issued auth token bound to
 * the worker with a nested `act` (step 5), the worker calling the resource with
 * that token (step 7), and single-level depth enforcement (step 8).
 */
test.describe.configure({ timeout: 60_000 });

/** Slice + parse the JSON object rendered in the selected step's token panel. */
async function decodedPayload(page: import('@playwright/test').Page): Promise<Record<string, unknown>> {
  const panel = page
    .locator('section.payload article.inspector details.token')
    .filter({ hasText: 'Decoded payload' });
  await expect(panel).toBeVisible();
  const text = await panel.locator('pre code').innerText();
  return JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1)) as Record<string, unknown>;
}

test('sub-agent flow binds parent_agent, the worker cnf, and a nested act', async ({ page }) => {
  await openTour(page);
  await selectFlow(page, TourMode.SubAgent);

  await runAll(page);

  // All eight in-process steps complete; no consent / poll parks the flow.
  await expect(doneSteps(page)).toHaveCount(8);
  await expect(page.locator('button.primary')).toHaveText('Done');

  // Step 2 — the worker's agent token carries the authoritative `parent_agent`
  // marker naming the parent, and the subject is the "+"-delimited sub-agent id.
  await selectStep(page, 1);
  const workerToken = await decodedPayload(page);
  expect(workerToken.parent_agent).toBe('aauth:aria@localhost:5400');
  expect(workerToken.sub).toBe('aauth:aria+worker1@localhost:5400');
  expect(workerToken.cnf).toBeTruthy();

  // Step 5 — the PS returns an auth token bound to the SUB-AGENT (agent + cnf),
  // whose act nests { sub: worker, act: { sub: parent } } for audit.
  await selectStep(page, 4);
  const authToken = await decodedPayload(page);
  expect(authToken.agent).toBe('aauth:aria+worker1@localhost:5400');
  expect(authToken.cnf).toBeTruthy();
  const act = authToken.act as Record<string, unknown>;
  expect(act.sub).toBe('aauth:aria+worker1@localhost:5400');
  const innerAct = act.act as Record<string, unknown>;
  expect(innerAct.sub).toBe('aauth:aria@localhost:5400');

  // Step 7 — the sub-agent calls the resource itself with the issued token.
  await selectStep(page, 6);
  await expect(page.locator('section.payload article.inspector h2')).toHaveText(
    /Sub-agent calls the resource with the token/,
  );

  // Step 8 — single-level depth: the AP refuses a sub-agent of a sub-agent.
  await selectStep(page, 7);
  await expect(
    page.locator('section.payload article.inspector'),
  ).toContainText('InvalidOperationException');
});

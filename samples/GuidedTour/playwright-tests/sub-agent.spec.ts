import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { openTour, selectFlow, doneSteps, selectStep, TourMode } from '../../../tests/e2e/helpers/tour';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';
import { completeWorkerConsent } from '../../../tests/e2e/helpers/worker-consent';

/**
 * Sub-Agents — parent-mediated workers, 7 steps through the live PS and AS.
 * Assert the wire artifacts the steps surface:
 * the sub-agent's `parent_agent` claim (step 2), the issued auth token bound to
 * the worker with a nested `act` (step 5), and the worker calling the resource
 * with that token (step 7).
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

for (const entry of ['picker', 'deep link'] as const) {
test(`sub-agent flow via ${entry} binds parent_agent, the worker cnf, and a nested act`, async ({ page }) => {
  if (entry === 'picker') {
    await openTour(page);
    await selectFlow(page, TourMode.SubAgent);
  } else {
    await page.goto('/tour?flow=SubAgent');
    await expect(page.locator('#flow-select')).toHaveValue(TourMode.SubAgent);
    await waitForInteractive(page, 'button.primary');
  }

  await page.getByRole('button', { name: 'Run all' }).click();
  const consent = page.locator('a.primary.approve.worker-consent');
  await expect(consent).toHaveText('Approve original caller at Person Server (1 of 3)');
  await expect(consent).toHaveAttribute('target', '_blank');
  await expect(page.getByText(/Consent 1 of 3/)).toBeVisible();
  const labels: string[] = [];
  await completeWorkerConsent(
    page,
    'a.worker-consent',
    async () => (await doneSteps(page).count()) === 7,
    async (_, round) => { labels.push(await consent.innerText()); },
  );
  expect(labels).toEqual([
    'Approve original caller at Person Server (1 of 3)',
    'Approve worker Wallet access at Person Server (2 of 3)',
    'Approve federated access at Access Server (3 of 3)',
  ]);

  // Complete the live consent/poll round and all seven displayed steps.
  await expect(doneSteps(page)).toHaveCount(7);
  await expect(page.locator('button.primary')).toHaveText('Done');

  // Step 2 — the worker's agent token carries the authoritative `parent_agent`
  // marker naming the parent, and the subject is the "+"-delimited sub-agent id.
  await selectStep(page, 1);
  const workerToken = await decodedPayload(page);
  expect(workerToken.parent_agent).toBe('aauth:aria@localhost');
  expect(workerToken.sub).toBe('aauth:aria+worker1@localhost');
  expect(workerToken.cnf).toBeTruthy();

  // Step 5 — the PS returns the AS token bound to the SUB-AGENT (agent + cnf).
  // The sub-agent is the top-level `agent`; act.agent names the parent that
  // mediated, followed by the original caller's upstream context.
  await selectStep(page, 4);
  const authToken = await decodedPayload(page);
  expect(authToken.agent).toBe('aauth:aria+worker1@localhost');
  expect(authToken.cnf).toBeTruthy();
  const act = authToken.act as Record<string, unknown>;
  expect(act.agent).toBe('aauth:aria@localhost');
  expect((act.act as Record<string, unknown>).agent).toBe('aauth:original@localhost');
  expect(authToken.iss).toBe('http://localhost:5500');
  expect(authToken.dwk).toBe('aauth-access.json');

  // Step 7 — the sub-agent calls the resource itself with the issued token.
  await selectStep(page, 6);
  await expect(page.locator('section.payload article.inspector h2')).toHaveText(
    /Sub-agent calls the resource with the token/,
  );
  await expect(page.locator('section.payload article.inspector')).toContainText('aauth:aria+worker1@localhost');
});
}

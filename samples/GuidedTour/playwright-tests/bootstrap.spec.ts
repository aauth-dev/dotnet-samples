import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { openTour, selectFlow, runAll, doneSteps, TourMode } from '../../../tests/e2e/helpers/tour';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Bootstrap — keygen + Agent Provider enrolment, 3 steps (AP configured). There
 * is no resource call in this flow; the result is the minted `aa-agent+jwt`. The
 * DoD here is that all three steps complete and the final step renders the agent
 * token whose decoded payload binds the tour agent's identity to the AP issuer.
 */
test.describe.configure({ timeout: 60_000 });

test('bootstrap enrols and mints an agent token', async ({ page }) => {
  await openTour(page);
  await selectFlow(page, TourMode.Bootstrap);

  await runAll(page);

  await expect(doneSteps(page)).toHaveCount(3);
  await expect(page.locator('button.primary')).toHaveText('Done');

  // Final step auto-selected; the enrolment yields an aa-agent+jwt. The token
  // header declares the AAuth agent-token type; the decoded payload binds the
  // tour agent's identity (sub) to the AP issuer with a cnf key.
  const inspector = page.locator('section.payload article.inspector');
  const header = inspector.locator('details.token', { hasText: 'Decoded header' });
  await expect(header.locator('pre code')).toContainText('aa-agent');

  const payloadPanel = inspector.locator('details.token', { hasText: 'Decoded payload' });
  const payloadText = await payloadPanel.locator('pre code').innerText();
  const payload = JSON.parse(
    payloadText.slice(payloadText.indexOf('{'), payloadText.lastIndexOf('}') + 1),
  ) as Record<string, unknown>;
  expect(payload.sub).toBe(Agents.tour);
  expect(payload.iss).toBe(Urls.agentProvider);
  expect(payload.cnf).toBeTruthy(); // proof-of-possession confirmation key
});

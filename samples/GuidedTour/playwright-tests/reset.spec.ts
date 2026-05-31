import { test, expect } from '@playwright/test';
import {
  openTour,
  selectFlow,
  runAll,
  selectStep,
  doneSteps,
  steps,
  TourMode,
} from '../../../tests/e2e/helpers/tour';

/**
 * Step inspector + Reset controls. After running a flow, each done step is
 * clickable and renders its captured payloads in the inspector; Reset clears the
 * timeline back to an unexecuted state.
 */
test.describe.configure({ timeout: 60_000 });

test('step inspector shows a selected step, then Reset clears the timeline', async ({ page }) => {
  await openTour(page);
  await selectFlow(page, TourMode.Autonomous);

  await runAll(page);
  await expect(doneSteps(page)).toHaveCount(6);

  // Selecting step 1 renders its inspector pane.
  await selectStep(page, 0);
  await expect(page.locator('section.payload article.inspector h2')).toContainText('1.');

  // Reset clears all executed steps and restores the "run a step" hint.
  await page.getByRole('button', { name: 'Reset' }).click();
  await expect(doneSteps(page)).toHaveCount(0);
  await expect(steps(page)).toHaveCount(6); // plan still rendered
  await expect(page.locator('section.payload')).toContainText('Run a step');
});

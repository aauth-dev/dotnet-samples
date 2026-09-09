import { expect, Locator } from '@playwright/test';

export async function expectRequestResponseArrows(diagram: Locator): Promise<void> {
  const messages = diagram.locator('.sequence-message:has(.sequence-response)');
  const count = await messages.count();
  expect(count).toBeGreaterThan(0);
  await expect(diagram.locator('.sequence-response')).toHaveCount(count);

  for (let index = 0; index < count; index++) {
    const message = messages.nth(index);
    const request = message.locator('.sequence-arrow:not(.sequence-response)');
    const response = message.locator('.sequence-response');
    await expect(request).toHaveCSS('border-top-style', 'solid');
    await expect(response).toHaveCSS('border-top-style', 'dashed');
    await expect(message.locator('.sequence-response-label')).not.toHaveText(/^response$/i);
    const requestClass = await request.getAttribute('class');
    const responseClass = await response.getAttribute('class');
    expect(requestClass?.includes('rightward')).toBe(!responseClass?.includes('rightward'));
  }

  const oneWay = diagram.locator('.sequence-message:not(.self):not(:has(.sequence-response))');
  for (let index = 0; index < await oneWay.count(); index++)
    await expect(oneWay.nth(index).locator('.sequence-arrow')).toHaveCount(1);
}

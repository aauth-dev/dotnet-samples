import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour,
  selectFlow,
  selectSigningMode,
  runAll,
  selectStep,
  expectResponse,
  readResponseJson,
  TourMode,
  SigningMode,
} from '../../../tests/e2e/helpers/tour';

/**
 * Identity-based access (no Person Server, 2 steps): the resource trusts the
 * agent's signature directly and returns 200 on the first signed call. Run for
 * the default AAuth jwt identity mode and each generic Signature-Key lesson;
 * assert the actual 200 result plus the exact mode/scheme the Profile resource
 * reports back, plus the identifying claim it surfaces.
 *
 *   Jwt      → agent-identity, scheme "jwt"     → identifier
 *   Hwk      → pseudonymous, scheme "hwk"       → jkt thumbprint
 *   Jwks     → agent-identity, scheme "jwks"    → kid
 *   JktJwt   → pseudonymous, scheme "jkt-jwt"   → jkt thumbprint
 */

const cases: Array<{
  mode: SigningMode;
  resultMode: string;
  scheme: string;
  idClaim: 'identifier' | 'jkt' | 'kid';
  generic: boolean;
}> = [
  { mode: SigningMode.Jwt, resultMode: 'agent-identity', scheme: 'jwt', idClaim: 'identifier', generic: false },
  { mode: SigningMode.Hwk, resultMode: 'pseudonymous', scheme: 'hwk', idClaim: 'jkt', generic: true },
  { mode: SigningMode.Jwks, resultMode: 'agent-identity', scheme: 'jwks', idClaim: 'kid', generic: true },
  { mode: SigningMode.JktJwt, resultMode: 'pseudonymous', scheme: 'jkt-jwt', idClaim: 'jkt', generic: true },
];

for (const { mode, resultMode, scheme, idClaim, generic } of cases) {
  test(`identity flow (${mode}) returns 200 with scheme ${scheme}`, async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Identity);
    await selectSigningMode(page, mode);
    if (generic) {
      await expect(page.locator('body')).toContainText('non-AAuth');
    }

    await runAll(page);

    // Step 2 ("Signed GET → 200") is the resource result. Inspect it and
    // assert the rendered status, then the exact claim structure.
    await selectStep(page, 1);
    await expectResponse(page, 200, [scheme]);

    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.signingMode).toBe(resultMode);
    expect(json.scheme).toBe(scheme);
    expect(typeof json[idClaim]).toBe('string');
    expect(String(json[idClaim])).not.toHaveLength(0);
  });
}

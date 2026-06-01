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
 * each of the three signing modes; assert the actual 200 result plus the exact
 * mode/scheme the WhoAmI resource reports back, plus the identifying claim it
 * surfaces (key thumbprint or key id).
 *
 *   Hwk      → pseudonymous, scheme "hwk"      → jkt thumbprint
 *   JwksUri  → agent-identity, scheme "jwks_uri" → kid
 *   JktJwt   → pseudonymous, scheme "jkt-jwt"  → jkt thumbprint
 */

const cases: Array<{
  mode: SigningMode;
  resultMode: string;
  scheme: string;
  idClaim: 'jkt' | 'kid';
}> = [
  { mode: SigningMode.Hwk, resultMode: 'pseudonymous', scheme: 'hwk', idClaim: 'jkt' },
  { mode: SigningMode.JwksUri, resultMode: 'agent-identity', scheme: 'jwks_uri', idClaim: 'kid' },
  { mode: SigningMode.JktJwt, resultMode: 'pseudonymous', scheme: 'jkt-jwt', idClaim: 'jkt' },
];

for (const { mode, resultMode, scheme, idClaim } of cases) {
  test(`identity flow (${mode}) returns 200 with scheme ${scheme}`, async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Identity);
    await selectSigningMode(page, mode);

    await runAll(page);

    // Step 2 ("Signed GET → 200") is the resource result. Inspect it and
    // assert the rendered status, then the exact claim structure.
    await selectStep(page, 1);
    await expectResponse(page, 200, [scheme]);

    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.mode).toBe(resultMode);
    expect(json.scheme).toBe(scheme);
    expect(typeof json[idClaim]).toBe('string');
    expect(String(json[idClaim])).not.toHaveLength(0);
  });
}

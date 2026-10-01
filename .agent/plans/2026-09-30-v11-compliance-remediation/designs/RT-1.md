# RT-1 — R01/R02/R03/R14 resource verification designs

## Verdicts

| Design | Finding | Verdict (SOUND / SOUND-WITH-CHANGES / UNSOUND) | Required change | Severity (HIGH/MEDIUM/LOW) |
|---|---|---|---|---|
| R01-audience-binding.md | SDK-01, A09-MED-001, A10-02, DOC-03 | SOUND | None. The design derives the resource audience once from `AddAAuthResource`, removes the token-`aud` fallback, and deliberately leaves PS/AS internal `UseAAuthVerificationCore` agent/JWKS paths fail-closed for accidental person/auth JWT carriers (R01-audience-binding.md:27-31, R01-audience-binding.md:51-55, R01-audience-binding.md:87). | LOW |
| R02-four-party-trust.md | SDK-02, A17-002, D09-01, D10-05 | SOUND-WITH-CHANGES | Pin the high-level three-party default to PS-issued auth tokens (`ExpectedAuthTokenDwk = aauth-person.json`) when `AccessServer == null`; reserve dual-DWK acceptance for an explicit mixed-mode opt-out plus issuer trust policy. Keep the proposed AS `dwk=aauth-access.json` pin for four-party and AS-response validation. | HIGH |
| R03-authorization-endpoint.md | SDK-08, SDK-18, A07/A08/A09/A03, SMP-04, DOC-04 | SOUND | None. The person-token access mode/marker, validated-token-type check, R0 extension seam for R3 without core→R3 dependency, resource-managed sample split, and 403 trust-denial mapping satisfy the cited requirements (R03-authorization-endpoint.md:30-40, R03-authorization-endpoint.md:64-70, R03-authorization-endpoint.md:100-102). | LOW |
| R14-jwt-verification.md | SDK-17, A01-H01, A01-M02, A03-HIGH-001, A19-HIGH-001, A21-TLS-01 | SOUND | None. The single cutover rejects unsupported `crit`, fixes app-specific `jwt` key resolution through a context verifier, applies zero expiration skew, removes `ChallengeOptions.AllowedSignatureKeySchemes`, centralizes Signature-Error writing, and pins SDK-owned TLS (R14-jwt-verification.md:26-36, R14-jwt-verification.md:40-43, R14-jwt-verification.md:60-63, R14-jwt-verification.md:98-102). | LOW |

## Details

R02 is still fail-open in the nominal three-party default. The design says `AccessServer == null` keeps open auth-token issuer trust and "may accept either auth-token `dwk` value" (R02-four-party-trust.md:31), while the current verifier accepts both auth-token DWKs (`src/AAuth/Tokens/TokenVerifier.cs:393-396`) and unset trust accepts any cryptographically verifiable issuer (`src/AAuth/Server/AAuthTrustPolicy.cs:66-69`, `src/AAuth/Server/AAuthTrustPolicy.cs:164-168`). The spec's generic verifier can understand both AS- and PS-issued auth tokens (#auth-token-verification, L1807-L1808), but the topology text distinguishes three-party as `dwk: aauth-person.json` and PS-AS/four-party as `dwk: aauth-access.json` (#ps-as-collapse, L1759-L1762), and says a resource with no AS is accepting PS-asserted identity/consent while retaining its own policy (#trust-posture-in-ps-asserted-access, L2866-L2868). As written, a malicious or merely unrelated AS can mint an AS-DWK auth token with this resource as `aud`; open three-party trust would treat it as an authorization assertion from outside the declared topology. Default `AccessServer == null` should therefore set `ExpectedAuthTokenDwk = AAuthConstants.DwkFiles.Person`; explicit mixed deployments can still opt back into `ExpectedAuthTokenDwk = null` with a `TokenDwk`-aware trust policy as the design already sketches (R02-four-party-trust.md:33, R02-four-party-trust.md:116-117).

## Cross-design conflicts and ordering

- Implement R01 before R02/R03 so every person/auth-token success is already bound to the resource `aud` (#person-token-verification, L913-L918; #auth-token-verification, L1810-L1815).
- R02 and R14 both modify `TokenVerifier`, `DefaultSignatureKeyResolver`, and auth-token verification. Coordinate the new companion verifier contract with R02's `expectedDwk` so app-specific `jwt` key resolution cannot bypass role-DWK pinning.
- R03 and R14 both touch `AAuthChallengeMiddleware`, `AAuthProblemDetails`, and verification error mapping. R14's shared helper owns 401 authentication/signature failures; R03's policy-denial branch must remain 403 with no `Signature-Error` or `Accept-Signature-*` per Signature-Key §5.3 (L1936-L1944).
- R02's `AAuthResourceOptions.AccessServer` should be the single high-level four-party declaration; do not let R03's access-mode metadata or R14's scheme policy become a second topology switch.

## Open questions the orchestrator must rule on (with proposed default)

1. **Should three-party default auth-token verification pin `dwk=aauth-person.json`?** Default: yes. Dual DWK is legitimate only for explicitly mixed resources with `ExpectedAuthTokenDwk = null` and a `TokenDwk`-aware trust policy.
2. **Should `AAuthTrust.Any` be allowed unchanged in four-party mode?** Default: only with an explicit mixed-mode DWK decision; otherwise throw or high-signal warn because it can undo AS-only issuer trust.
3. **Which design owns the final `expectedDwk` API shape?** Default: R02 owns the option and TokenVerifier parameter; R14 must thread it through the new verifier/resolver contract without adding compatibility shims.

# R02 — Four-party trust and AS-issued tokens

Findings: SDK-02, A17-002, D09-01, D10-05. Spec: `#overview-federated` L386-L431, `#policy-evaluation-points` L446-L456, `#auth-token-delivery` L1644-L1661, `#ps-as-collapse` L1757-L1765, `#auth-token-verification` L1802-L1815, `#access-server-metadata` L2073-L2098, `#trust-posture-in-ps-asserted-access` L2864-L2871. Files read: `src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs`, `src/AAuth/Server/AAuthTrust.cs`, `src/AAuth/Server/AAuthTrustPolicy.cs`, `src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs`, `src/AAuth/Server/Verification/AAuthVerificationOptions.cs`, `src/AAuth/Server/Verification/TrustConfigDiagnostics.cs`, `src/AAuth/DependencyInjection/AAuthResourceOptions.cs`, `src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs`, `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs`, `src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs`, `src/AAuth/Server/Challenge/ChallengeOptions.cs`, `src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs`, `src/AAuth/Tokens/AuthTokenResponseValidator.cs`, `src/AAuth/Tokens/TokenVerifier.cs`, `src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs`, targeted tests and samples/docs listed below.

## Problem restated (verified)

SDK-02 is still present in the resource pipeline. In four-party access, the resource token names the resource's AS as `aud`; the PS federates to that AS; the AS decides whether to issue the auth token; and the agent presents that token to the resource (`#overview-federated`, L386-L430). The spec also separates the policy vantage points: the AS issues auth tokens on the resource's behalf, and the resource enforces the resulting token (`#policy-evaluation-points`, L452-L453). Current `UseAAuth` only feeds `AAuthServerOptions.AccessServer` into the challenge middleware (`AAuthEndpointExtensions.cs:189-197`); the verification options receive only `ResourceIdentifier` and `Trust` (`AAuthEndpointExtensions.cs:174-186`). If no auth-token issuer trust is configured, `AAuthTrustRule` has no configured parts and accepts any issuer (`AAuthTrustPolicy.cs:67-91`, `:164-168`). The middleware therefore asks only whether the token issuer is trusted as an `AuthTokenIssuer` (`AAuthVerificationMiddleware.cs:233-240`) and accepts a verifiable PS-issued `aa-auth+jwt` with `dwk: aauth-person.json` even when this resource declared an AS. That is the AS-policy bypass described by SDK-02.

The current code does have examples that mitigate SDK-02 manually: Wallet pins `Trust.AuthTokenIssuers` to the AS and sets `AccessServer` (`samples/MockResourceServers/Wallet/Program.cs:79-81`), and Catalog pins manual verification to its AS (`samples/MockResourceServers/Catalog/Program.cs:56-63`). Those do not change the unsafe SDK default.

A17-002 is also present. Auth-token delivery requires the PS to verify an AS `200` response using the AS's JWKS (`#auth-token-delivery`, L1646-L1648); AS metadata publishes the AS `jwks_uri` (`#access-server-metadata`, L2094-L2096). `AuthTokenResponseValidator.ValidateAsync` calls `TokenVerifier.VerifyAuthTokenWithJwksAsync` without an expected `dwk` (`AuthTokenResponseValidator.cs:80-87`). `TokenVerifier.VerifyWithIssuerKeyAsync` accepts both `aauth-person.json` and `aauth-access.json` for auth tokens (`TokenVerifier.cs:393-396`) and discovers metadata using the token's own `dwk` (`TokenVerifier.cs:406`). A collocated or misconfigured AS can therefore return an auth token with `iss` equal to the AS URL but `dwk: aauth-person.json`, and the PS verifies it through person-role metadata instead of the AS role metadata.

The docs findings are verified: root README says unset `Trust.AuthTokenIssuers` or `AAuthTrust.Any` accepts any verifiable PS as “the spec default” (`README.md:222`), and the DI reference repeats that advice (`docs/reference/dependency-injection.md:265-270`) while also describing `AccessServer` as the resource-token recipient (`docs/reference/dependency-injection.md:291-296`). That wording is correct only for three-party PS-asserted access, where the resource has no AS and applies its own policy to PS-issued claims (`#trust-posture-in-ps-asserted-access`, L2866-L2868).

## Candidate fixes

| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
|---|---|---|---|---|---|
| 1 | Documentation and sample-only caveat: keep SDK defaults, update README/DI docs to tell four-party resources to set `Trust.AuthTokenIssuers.Allowed = { AccessServer }`. | Smallest code change; preserves existing behavior. | Leaves the SDK fail-open for the exact four-party footgun; does not fix A17-002; every consumer must remember two settings. | Weak. The four-party model makes the AS the policy issuer (`#overview-federated`, L388-L430; `#policy-evaluation-points`, L452-L453). | Violates C6 because the SDK does not own spec-mandated mechanics; violates the brief's fail-closed preference. |
| 2 | Derive four-party verification defaults from one effective `AccessServer`: default auth-token issuer trust to that AS, require `dwk: aauth-access.json`, and make AS-response validation pin `aauth-access.json`. Three-party keeps the open PS-asserted default. | Fixes SDK-02 and A17-002 by default; `AccessServer` becomes the mode selector; no per-consumer HTTP plumbing; preserves explicit trust-policy escape hatch. | Adds public options and verifier surface; mixed PS+AS acceptance needs an explicit advanced policy. | Strong. Three-party remains `dwk: aauth-person.json`; PS-AS collapse/four-party uses `dwk: aauth-access.json` (`#ps-as-collapse`, L1761-L1762), and AS delivery uses AS JWKS (`#auth-token-delivery`, L1648). | Best fit: C5 identity once, C6 mechanics in SDK, C9 async trust policy, C7 DWK constants. |
| 3 | Introduce an explicit `AAuthResourceMode`/`AuthorizationTopology` enum (`ThreeParty`, `FourParty`, `Mixed`) and require callers to choose it independently of `AccessServer`. | Very explicit and could model mixed deployments cleanly. | Duplicates state with `AccessServer`, risks contradictory config, and turns metadata `AccessMode` into a topology knob it is not. | Good if perfectly validated, but more moving pieces. | Poor C5 fit: role identity and mode are declared twice. |

## Recommendation

Implement candidate 2.

Make the resource's effective Access Server the single four-party mode signal. The canonical high-level declaration should be `AAuthResourceOptions.AccessServer` (new), because `AAuthResourceOptions` already owns the resource identifier, keys, metadata, and eager single-instance role configuration (`AAuthResourceOptions.cs:14-24`, `:100-113`; ASL says the resource role remains a single eager `IOptions<AAuthResourceOptions>` instance). `AAuthResourceOptions.AccessMode` must remain only the advisory metadata `access_mode`; it does not identify the AS and must not be overloaded as topology (`AAuthResourceOptions.cs:100-105`). The low-level primitives keep `ChallengeOptions.AccessServer` (`ChallengeOptions.cs:34-38`) and existing `AAuthServerOptions.AccessServer` (`AAuthEndpointRequirement.cs:42-47`) as overrides, but docs should teach high-level users to set the AS once in `AddAAuthResource`.

Default behavior by effective mode:

- **Three-party** (`AccessServer == null`): keep unset auth-token trust open with the existing warning, but reword it as the PS-asserted default only. Auth-token verification may accept either auth-token `dwk` value because the low-level verifier is shared, but resource docs should describe PS-issued `aauth-person.json` as the normal three-party value.
- **Four-party** (`AccessServer != null`): derive a normalized verification policy before constructing middleware. If no auth-token issuer policy/rule/DI service is configured, set the default issuer allow-list to exactly `{ AccessServer }`. Independently require auth tokens on that pipeline to carry `dwk: AAuthConstants.DwkFiles.Access` (`aauth-access.json`). This is the SDK default data policy; callers can override only by an explicit trust policy plus an explicit low-level `ExpectedAuthTokenDwk = null`/mixed-mode setting (name bikeshedding below).
- **Mixed PS-asserted and AS-issued auth tokens**: the spec's generic auth-token verification admits either AS or PS `dwk` (`#auth-token-verification`, L1808), so a resource can deliberately accept both, but it is not the default when an AS is declared because that bypasses AS policy. Express mixed support as advanced composition: direct `UseAAuthVerification`/branch-specific middleware or an explicit `IAAuthTrustPolicy` that inspects `AAuthTrustContext.TokenDwk`, plus `ExpectedAuthTokenDwk = null`. Do not make `.UseAAuth(o => o.AccessServer = ...)` silently mixed.

For A17-002, `AuthTokenResponseValidator` must always verify AS responses with expected `dwk: aauth-access.json`. The PS asked an AS for a token, so there is no mixed-mode exception in this validator.

## Public API delta

Yes.

Added / changed members:

- `AAuthResourceOptions.AccessServer: string?` — canonical high-level AS issuer URL for four-party resources. Validation: absolute HTTPS URL with the same loopback HTTP allowance as other role identifiers.
- `AAuthResourceMetadataOptions.AccessServer: string?` (internal/public-but-SDK metadata options) so `UseAAuth` and `MapAAuthResource` can derive pipeline defaults from `AddAAuthResource` without duplicating configuration.
- `AAuthVerificationOptions.ExpectedAuthTokenDwk: string?` (or `RequiredAuthTokenDwk`; prefer `ExpectedAuthTokenDwk` to match `TokenVerifier.VerifyAuthToken` wording). `null` means dual-dwk; four-party composition sets `AAuthConstants.DwkFiles.Access`.
- `AAuthTrustContext.TokenDwk: string?` so async trust policies can pin expected `dwk` per trusted party/issuer. Populate it for JWT assertions before calling `IAAuthTrustPolicy.IsTrustedAsync`.
- `TokenVerifier.VerifyAuthTokenWithJwksAsync(..., string? expectedDwk = null)` and private `VerifyWithIssuerKeyAsync(..., string? expectedDwk = null)`. When `expectedDwk` is non-null, reject a token whose payload `dwk` differs and discover metadata using the expected `dwk`.
- Optional helper/internal factory such as `AAuthTrustDefaults.ForResource(effectiveAccessServer, trust, services)` is acceptable, but avoid a new public topology enum.

Changed semantics:

- `UseAAuth` and `MapAAuthResource` in four-party mode derive fail-closed auth-token issuer and `dwk` defaults. Existing explicit data/delegate/DI trust still participates through the C9 ladder, but the default is no longer open when an AS is declared.
- `AAuthTrust.Any` remains valid only as an explicit “I intend open trust” marker. In four-party mode it must also require either an explicit mixed-mode DWK choice or log a high-signal warning; otherwise `AAuthTrust.Any` would reintroduce SDK-02.

ApiSurface impact: additive public members plus changed behavior. No compatibility shim or obsolete overload is needed (C1).

## Wire effect

- Four-party resources that previously accepted a verifiable PS-issued auth token directly now reject it before the endpoint handler. The HTTP response is the existing verification failure path (`401` with the SDK's signature/JWT failure format); no new success-body shape is introduced.
- Four-party challenges still send the same resource token shape: resource `iss`, AS `aud`, presented token metadata, and requested scope (`AAuthChallengeMiddleware.cs:166-175`). The change is that the follow-up auth token must be issued by the AS and carry `dwk: aauth-access.json`.
- PS federation changes for malformed AS success responses: an AS `200` auth token with `dwk: aauth-person.json` now fails delivery verification. Per spec, if the PS cannot obtain a verifiable AS auth token, it returns `as_unreachable` rather than relaying the token (`#auth-token-delivery`, L1656-L1658). Terminal AS errors are still relayed unchanged.
- Three-party resources with no `AccessServer` keep the current open PS-asserted wire behavior, including the startup warning, but docs will identify it as three-party-only.

## Implementation sketch

1. **Centralize the resource AS declaration.** Add `AAuthResourceOptions.AccessServer` and copy it into `AAuthResourceMetadataOptions` in `AAuthResourceServiceCollectionExtensions` near the existing metadata projection (`AAuthResourceServiceCollectionExtensions.cs:104-124`). Validate it in `AddAAuthResource` beside `Issuer` validation (`AAuthResourceServiceCollectionExtensions.cs:57-59`).
2. **Flow the effective AS into both challenge and verification.** In `AAuthEndpointExtensions.UseAAuth`, compute `effectiveAccessServer = opts.AccessServer ?? resourceMetadata?.AccessServer` beside `resourceIdentifier` (`AAuthEndpointExtensions.cs:136-139`). Pass it to `ChallengeOptions.AccessServer` (`AAuthEndpointExtensions.cs:189-197`) and use it to derive verification options (`AAuthEndpointExtensions.cs:174-186`). In `MapAAuthResource`, pass `metadataOptions.AccessServer` to `UseAAuthChallengeCore`; today the mapper never sets `ChallengeOptions.AccessServer` (`AAuthApplicationBuilderExtensions.cs:236-244`).
3. **Derive fail-closed four-party trust.** Add a small internal normalizer that returns `(AAuthTrustOptions Trust, string? ExpectedAuthTokenDwk, bool derivedIssuerTrust)`. If effective AS is set and `Trust.IsConfigured(AuthTokenIssuer, services)` is false, create a copy whose `AuthTokenIssuers.Allowed = new HashSet<string> { effectiveAccessServer }`. Set `ExpectedAuthTokenDwk = AAuthConstants.DwkFiles.Access` for every four-party auth-token verification path unless an explicit mixed-mode option is set. Do not mutate the caller's options instance.
4. **Pin `dwk` before resolving issuer keys.** Add `ExpectedAuthTokenDwk` to `AAuthVerificationOptions`. In `AAuthVerificationMiddleware.InvokeAsync`, after `SignatureKeyParser.ParseAny` and before `_resolver.ResolveAsync` (`AAuthVerificationMiddleware.cs:114-116`), if the assertion `typ` is `aa-auth+jwt` and `ExpectedAuthTokenDwk` is non-null, compare the parsed payload `dwk`; reject on mismatch without fetching person-role metadata. Also pass `ExpectedAuthTokenDwk` to the final `_tokenVerifier.VerifyAuthToken` call (`AAuthVerificationMiddleware.cs:237-240`).
5. **Expose `dwk` to trust policy.** Add `TokenDwk` to `AAuthTrustContext` and thread it through `AAuthTrustOptions.IsTrustedAsync` calls. The middleware has parsed payload data at trust time (`AAuthVerificationMiddleware.cs:233-246`); PS/AS federation checks that evaluate URL-only trust can leave it null.
6. **Pin AS response validation.** Extend `TokenVerifier.VerifyAuthTokenWithJwksAsync` and `VerifyWithIssuerKeyAsync`. If `expectedDwk` is set, validate the payload `dwk` equals it, and call `metadata.GetUrl(iss, expectedDwk)` rather than `metadata.GetUrl(iss, tokenDwk)`. In `AuthTokenResponseValidator.ValidateAsync`, pass `AuthTokenBuilder.AccessDwk` / `AAuthConstants.DwkFiles.Access` (`AuthTokenResponseValidator.cs:80-87`). This closes the A17-002 metadata selection bug.
7. **Diagnostics.** Update `TrustConfigDiagnostics.Validate` text (`TrustConfigDiagnostics.cs:21-35`) to distinguish three-party open trust from four-party derived trust. Add a four-party diagnostic: if effective AS is set and explicit auth-token trust is open (`AAuthTrust.Any`) or a custom DI policy hides the data rule, warn that the SDK cannot prove AS-only trust and that `TokenDwk` must be checked. If effective AS is set and a simple `Allowed` list excludes the AS, throw or log an error at startup because the resource will challenge for a token it refuses.
8. **Docs and samples.** Replace open-trust prose with the three-party/four-party caveat and update four-party samples to use the canonical `AAuthResourceOptions.AccessServer` where they use `AddAAuthResource`.

## Tests

- `tests/AAuth.Conformance/AuthTokens/AuthTokenDeliveryTests`: add `RejectsAsResponseWithPersonDwk`. Negative control: build a token with `iss = AsIssuer`, `dwk = aauth-person.json`, valid `aud/cnf/sub/ps/scope/exp`, signed by a key served from `/.well-known/aauth-person.json`. `AuthTokenResponseValidator.ValidateAsync` must reject and must not accept the person-role JWKS. Positive control: current `ValidToken_Accepted` still accepts `dwk = aauth-access.json`.
- `tests/AAuth.Conformance/AuthTokens/DualDwkTests`: keep `expectedDwk: null` dual-dwk tests, and add `ExpectedAccessDwk_RejectsPersonDwk` for `TokenVerifier.VerifyAuthToken` / `VerifyAuthTokenWithJwksAsync` so the low-level primitive remains explicit.
- `tests/AAuth.Conformance/HttpSignatures/VerificationMiddlewareTests` or new `FourPartyTrustTests`: start a resource with `AddAAuthResource(o => { o.Issuer = ResourceId; o.AccessServer = AsIssuer; ... })` and `UseAAuth`/`MapAAuthResource` with no `Trust.AuthTokenIssuers`. Positive: AS-issued `dwk=aauth-access.json` token succeeds. Negative SDK-02 control: PS-issued `dwk=aauth-person.json` token for the same resource and scope is rejected. Second negative: token `iss=AsIssuer` but `dwk=aauth-person.json` is rejected.
- `tests/AAuth.Tests/DependencyInjection/AAuthResourceDITests`: assert `AccessServer` is stored in the metadata/options projection and invalid URLs are rejected.
- `tests/AAuth.Tests/Integration/MockPersonServerFederationTests`: add an AS stub returning a person-role `dwk` auth token; PS should return the federation failure (`as_unreachable` per current error mapping) instead of relaying it. Existing `Token_FederatesToAccessServer_WhenResourceAudIsAs` remains the positive `dwk=access` control.
- Documentation/snippet tests under `tests/AAuth.Tests/Api/DocumentationSnippetContext.cs`, `SnippetCompilationTests.cs`, and `DocumentationInventory.cs`: update expected snippets if `AAuthResourceOptions.AccessServer` is introduced.

No build/test/restore should be run during this design task.

## Samples and docs to update

Samples from `samples/MockResourceServers` grep:

- `Wallet/Program.cs` — currently correct by manual AS allow-list plus `o.AccessServer` (`:79-81`); update to canonical `AddAAuthResource(o.AccessServer = accessServerUrl)` and remove redundant auth-token issuer allow-list if relying on the new default. Keep explicit `PersonServers` for person-token trust.
- `Catalog/Program.cs` — manual `UseAAuthVerification` pins auth-token issuer to `access` (`:56-63`), and `R3Challenge` mints `Audience = access` (`:77-78`). Add `ExpectedAuthTokenDwk = aauth-access.json` or route through the new four-party helper.
- `Bookings/Program.cs` — `R3Challenge` uses `Audience = accessServerUrl` (`:307-314`), but manual verification uses `AAuthVerificationOptions` without expected `dwk` (`:345-349`, `:433-435`) and direct `VerifyAuthTokenWithJwksAsync` without expected `dwk` (`:400-407`). Add AS `dwk` pinning and optionally `AAuthResourceOptions.AccessServer`.
- `Calendar/Program.cs`, `Trips/Program.cs`, `Documents/Program.cs` — three-party PS allow-list samples; no four-party behavior change, but comments should say they are PS-asserted examples.
- `Inbox/Program.cs` — uses `AAuthTrust.Any` only to suppress an unused auth-token warning (`:88`); with improved diagnostics it should not need an auth-token trust declaration, or the comment must say it is not a four-party resource.
- `Bookings/appsettings.json`, `Bookings/README.md`, `Wallet/README.md` — describe that `AAuth:AccessServer` now drives both resource-token audience and AS-only auth-token verification.

Docs to update:

- `README.md:222` — qualify open auth-token trust as three-party only; add four-party example with `AAuthResourceOptions.AccessServer` and default AS-only trust.
- `docs/reference/dependency-injection.md:256-296` — update resource options table and prose for `AccessServer`, `ExpectedAuthTokenDwk`, and the three-party caveat.
- `docs/server/verification-middleware.md:62-92`, `docs/server/authn-authz.md:85-86`, `docs/server/authorization-policies.md:110-113`, `docs/server/challenge-middleware.md:70-93`, `docs/server/resource-metadata.md:76-102` — distinguish low-level three-party open trust from high-level four-party derived AS trust.
- `docs/workflows/federated-access.md` — resource-side code should show setting the AS once and relying on AS-issued `dwk=aauth-access.json`; PS-side open `Trust.AccessServers` prose remains a separate decision.
- `docs/workflows/rich-resource-requests.md` — keep AS-side `Trust.PersonServers` text but update Bookings resource notes for AS `dwk` pinning.

## Dependencies and conflicts with other Rnn

- **R01** resource audience binding: both designs touch `AAuthVerificationOptions` and `AAuthVerificationMiddleware`. R01 should set the resource `aud`; R02 sets expected auth-token issuer role/`dwk`.
- **R03** authorization endpoint/access-mode gating: `AAuthResourceOptions.AccessMode` must stay metadata/advisory. Do not solve R02 by overloading access modes.
- **R07** federation collapse: PS-AS collapse also requires AS-issued `dwk=aauth-access.json` (`#ps-as-collapse`, L1761-L1762). R02's `AuthTokenResponseValidator` and verifier pinning are prerequisites but do not implement collapse routing.
- **R14** JWT/verification hygiene: changes to `TokenVerifier`, `DefaultSignatureKeyResolver`, and signature error formatting must be coordinated there.
- **R18/R19** samples and docs sweeps: R02 owns the trust/topology wording; broad README/conformance claim rewrites may be collated by R19.

## Open questions (with proposed default)

1. **Should an explicit `Trust.AuthTokenIssuers.Allowed` in four-party mode merge with the declared AS?** Proposed default: no implicit merge. If the user configures issuer data, respect it, but startup diagnostics should throw/warn when the declared AS is absent because the resource will issue AS-audience challenges it cannot accept.
2. **What is the exact opt-out name for mixed PS+AS auth-token acceptance?** Proposed default: `AAuthVerificationOptions.ExpectedAuthTokenDwk = null` is the low-level opt-out; high-level `UseAAuth` with `AccessServer` does not expose a one-line mixed switch. Mixed resources should use branch-specific pipelines or a custom `IAAuthTrustPolicy` inspecting `TokenDwk`.
3. **Should `AAuthTrustRule` grow data-level DWK pinning, or is `TokenDwk` on `AAuthTrustContext` enough?** Proposed default: start with context + `ExpectedAuthTokenDwk` for the SDK defaults; add a data map only if implementation finds a sample or test that needs mixed issuer/DWK pairs without a custom policy.
4. **Should existing `AAuthServerOptions.AccessServer` be kept as public low-level override?** Proposed default: yes. It is a primitive override consistent with C2; docs should steer normal resource hosts to `AAuthResourceOptions.AccessServer` so identity is declared once.

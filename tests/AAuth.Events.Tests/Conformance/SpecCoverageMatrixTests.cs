using System.Reflection;

namespace AAuth.Events.Tests.Conformance;

public sealed class SpecCoverageMatrixTests
{
    private sealed record Requirement(
        string Id,
        string Lines,
        bool InScope,
        string[] Tests,
        string LocalRuling);

    private static readonly Requirement[] Matrix =
    [
        new("metadata.event_endpoint", "L192", true,
            ["MetadataCacheRotationEndpointChangeAndUrlPolicyAreIntegrated"],
            "AP metadata is served and the resource resolves its current endpoint."),
        new("subscribe.alg.none", "L212", true,
            ["NoneUnsupportedAndMissingAlgorithmsAreRejected"],
            "Events accepts EdDSA/ES256 only and rejects none."),
        new("subscribe.aud.resource", "L221", true,
            ["ResourceAudienceMustMatchTheResourceUrl", "RegistrationCarriesIssuerSubjectAudienceEidAndTimes"],
            "The registration verifier enforces the resource audience."),
        new("subscribe.exp.resource", "L225", true,
            ["ExpiredTokenIsRejectedByCoreVerifier", "InvalidAudienceAndExpiredTimesMapWithoutHandlerInvocation"],
            "Expired subscribe credentials cannot reach registration policy."),
        new("subscribe.max_uses.ap", "L229", true,
            ["ApDurabilityBindsResourceAudienceExpiryAndTokenHashAtomically"],
            "The durable AP store atomically enforces the finite allowance."),
        new("registration.verify.type", "L270-L271", true,
            ["PublicSubscriptionFlowsFromApIssuanceToResourceDeliveryAndAgent", "WrongTypeAndDomainKeyAreRejectedByReader"],
            "The public endpoint verifies the subscribe-token profile."),
        new("registration.verify.dwk", "L271-L272", true,
            ["WrongTypeAndDomainKeyAreRejectedByReader", "MissingOrUnknownJwtKeyAndEidAreUnauthorizedOrMalformed"],
            "The AP well-known domain and JWKS are required."),
        new("registration.verify.signature", "L272", true,
            ["CnfMustMatchTheAgentHttpSignatureKey", "RegistrationRequiresTheExactHttpSignatureComponentSequence"],
            "The cnf key and HTTP signature are both verified."),
        new("registration.verify.time", "L273", true,
            ["FutureIssuedTokenIsRejectedByCoreVerifier", "ExpiredTokenIsRejectedByCoreVerifier"],
            "iat/exp validation uses a controllable clock."),
        new("registration.verify.audience", "L274", true,
            ["ResourceAudienceMustMatchTheResourceUrl", "InvalidAudienceAndExpiredTimesMapWithoutHandlerInvocation"],
            "The resource URL is an authorization boundary."),
        new("registration.verify.cnf", "L275", true,
            ["CnfMustMatchTheAgentHttpSignatureKey"],
            "The HTTP signing key must match cnf.jwk."),
        new("registration.verify.eid", "L276", true,
            ["EmptyEventIdIsRejectedByIssuanceAndReader", "MissingOrUnknownJwtKeyAndEidAreUnauthorizedOrMalformed"],
            "An eid is mandatory and non-empty."),
        new("registration.public", "L285", true,
            ["PublicSubscriptionFlowsFromApIssuanceToResourceDeliveryAndAgent"],
            "Public registration uses only the subscribe token."),
        new("registration.protected.agent", "L302-L305", true,
            ["ProtectedSubscriptionIsAgentBoundAndTicketIsSingleUseUnderRace"],
            "Protected tickets are checked against the token subject."),
        new("registration.protected.single_use", "L305", true,
            ["ProtectedSubscriptionIsAgentBoundAndTicketIsSingleUseUnderRace"],
            "Ticket consumption is atomic and a duplicate loses deterministically."),
        new("registration.protected.path", "L330-L339", true,
            ["ProtectedRegistrationBindsPathBaseAndEscapedOpaqueTicket", "ProtectedRegistrationRejectsSignaturePathSubstitutionBeforeHandler"],
            "The signed escaped path carries the opaque ticket."),
        new("event.aud.agent", "L356", true,
            ["AudienceMustMatchTheAgentIdentifier", "PublicSubscriptionFlowsFromApIssuanceToResourceDeliveryAndAgent"],
            "Agent verification requires its configured identifier."),
        new("event.eid.subscription", "L357", true,
            ["PublicSubscriptionFlowsFromApIssuanceToResourceDeliveryAndAgent", "DistinctEventsPreparedAtTheSameTimeHaveDistinctJtiAndBothApply"],
            "The resource carries the registered eid into every event token."),
        new("event.exp.agent", "L359", true,
            ["ExpiredEventTokenIsNotActionable", "FutureIssuedAtIsRejected"],
            "Expired or future event tokens are not actionable."),
        new("delivery.signature_key", "L364-L374", true,
            ["EventJwtIsTheHttpSignatureKeyAndDigestCoversExactBytes", "EventTokenAndOptionalJsonHaveTheExactWireShape"],
            "The event JWT is the Signature-Key carrier and body bytes are preserved."),
        new("delivery.ap.jwt", "L404.1-L404.2", true,
            ["ApVerifiesTokenThenHttpThenSubscriptionBeforeDurableMutation", "EventProfileRejectsWrongTypeOrDomainKey"],
            "The AP endpoint resolves and validates the event JWT."),
        new("delivery.ap.http", "L404.3", true,
            ["ApVerifiesTokenThenHttpThenSubscriptionBeforeDurableMutation", "EventJwtIsTheHttpSignatureKeyAndDigestCoversExactBytes"],
            "The resource key authenticates both JWT and HTTP signature."),
        new("delivery.ap.lookup", "L404.4", true,
            ["UnknownSubscriptionIsNotActionableAndDoesNotMutateDurableState"],
            "Unknown eids do not mutate durable state."),
        new("delivery.ap.resource", "L404.5", true,
            ["WrongResourceAndAudienceAreRejectedBeforeMutation"],
            "The AP enforces the resource binding."),
        new("delivery.ap.expiry", "L404.6", true,
            ["ExpiredAndFutureEventTokensAreRejectedWithoutMutation", "ExpiredSubscriptionIsNotActionableAndDoesNotMutateDurableState"],
            "Expired event and subscription records are rejected."),
        new("delivery.ap.max_uses", "L404.7", true,
            ["ConcurrentDistinctFinalUsesAllowOnlyOneDurableCommit", "ApDurabilityBindsResourceAudienceExpiryAndTokenHashAtomically"],
            "Final-use races have one durable winner."),
        new("delivery.ap.audience", "L404.8", true,
            ["WrongResourceAndAudienceAreRejectedBeforeMutation"],
            "The AP enforces the subscribed agent audience."),
        new("delivery.accepted.durable", "L415", true,
            ["DurableFailureNeverReturns202OrConsumesAUse", "ApDurabilityBindsResourceAudienceExpiryAndTokenHashAtomically"],
            "202 is emitted only after the store commits."),
        new("delivery.remaining_uses", "L415-L421", true,
            ["ConcurrentDistinctFinalUsesAllowOnlyOneDurableCommit", "AcceptedResponsesAllowNoBodyEmptyObjectAndRemainingUses"],
            "Finite subscriptions report non-negative remaining_uses."),
        new("delivery.statuses", "L425-L428", true,
            ["DeliveryMapsProtocolStatusesWithoutSuccessFallback", "WrongResourceAndAudienceAreRejectedBeforeMutation"],
            "The AP status mapping is exercised without success fallback."),
        new("agent.verify.profile", "L438-L440", true,
            ["ValidEventTokenVerifiesAllAgentClaimsAndResourceKey", "EventProfileRejectsWrongTypeOrDomainKey"],
            "The agent verifies the event profile and resource JWKS."),
        new("agent.verify.audience", "L441-L442", true,
            ["AudienceMustMatchTheAgentIdentifier"],
            "The agent rejects a different audience."),
        new("agent.verify.expiry", "L443", true,
            ["ExpiredEventTokenIsNotActionable", "FutureIssuedAtIsRejected"],
            "The agent applies event temporal policy."),
        new("agent.context", "L444", true,
            ["UnknownContextIsTypedAndNonActionable", "ContextLookupPrecedesDeduplication"],
            "Local eid context is application-owned and required for action."),
        new("agent.dedup", "L445", true,
            ["SameTimeEventsWithSameEidAndDistinctJtiAreBothAccepted", "ExactTokenReplayIsNonActionable", "SameTimeDistinctJtisAreAcceptedAndEachExactRetryIsIdempotent"],
            "Exact compact-token retries deduplicate while distinct jtis remain distinct."),
        new("discovery.security_scheme", "L484", true,
            ["AsyncApi_validator_checks_aauth_declarations_but_ignores_action"],
            "AsyncAPI AAuth security declarations are validated."),
        new("scope.resource_binding", "L578", true,
            ["WrongResourceAndAudienceAreRejectedBeforeMutation"],
            "A resource cannot deliver for another resource's eid."),
        new("ticket.short_lived", "L594-L598", true,
            ["ProtectedTicketOutcomesAreResourceControlled", "ProtectedSubscriptionIsAgentBoundAndTicketIsSingleUseUnderRace"],
            "The test resource models expiry and rejects expired tickets."),
        new("ticket.single_use", "L594-L598", true,
            ["ProtectedSubscriptionIsAgentBoundAndTicketIsSingleUseUnderRace"],
            "The test resource invalidates a ticket on first successful registration."),
        new("ticket.agent_binding", "L598", true,
            ["ProtectedSubscriptionIsAgentBoundAndTicketIsSingleUseUnderRace", "ProtectedTicketIsBoundToTheSubscribeTokenAgent"],
            "The ticket subject binding is enforced before consumption."),
        new("transport.ap_to_agent", "L430-L435", false,
            [],
            "Out of scope by the Phase 0 ruling: AP-to-agent transport is platform-dependent; the durable receipt is handed to EventTokenVerifier in-process.")
    ];

    [Fact]
    [Trait("Spec", "Events L190-L617; executable coverage matrix")]
    public void EveryNormativeRequirementHasOneUniqueExecutableRuling()
    {
        Assert.NotEmpty(Matrix);
        Assert.Equal(
            Matrix.Length,
            Matrix.Select(requirement => requirement.Id).Distinct(StringComparer.Ordinal).Count());

        var methods = typeof(SpecCoverageMatrixTests).Assembly
            .GetTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            .Select(method => method.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains(Matrix, requirement =>
            !requirement.InScope &&
            requirement.Id == "transport.ap_to_agent" &&
            requirement.LocalRuling.Contains("out of scope", StringComparison.OrdinalIgnoreCase));

        foreach (var requirement in Matrix)
        {
            Assert.False(string.IsNullOrWhiteSpace(requirement.Id));
            Assert.False(string.IsNullOrWhiteSpace(requirement.Lines));
            Assert.False(string.IsNullOrWhiteSpace(requirement.LocalRuling));
            if (!requirement.InScope)
            {
                Assert.Empty(requirement.Tests);
                continue;
            }

            Assert.NotEmpty(requirement.Tests);
            Assert.All(requirement.Tests, test =>
            {
                Assert.False(string.IsNullOrWhiteSpace(test));
                Assert.Contains(test, methods);
            });
        }
    }
}

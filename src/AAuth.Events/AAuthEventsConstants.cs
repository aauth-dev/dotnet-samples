namespace AAuth.Events;

/// <summary>Wire constants shared by the AAuth Events roles.</summary>
public static class AAuthEventsConstants
{
    /// <summary>The compact JWT type for AP-issued subscribe tokens.</summary>
    public const string SubscribeTokenType = "aa-subscribe+jwt";
    /// <summary>The compact JWT type for resource-issued event tokens.</summary>
    public const string EventTokenType = "aa-event+jwt";
    public const string SubscribeJwtType = SubscribeTokenType;
    public const string EventJwtType = EventTokenType;

    /// <summary>The fixed subscribe-token domain/key value.</summary>
    public const string AgentDwk = "aauth-agent.json";
    /// <summary>The fixed event-token domain/key value.</summary>
    public const string ResourceDwk = "aauth-resource.json";
    public const string SubscribeDwk = AgentDwk;
    public const string EventDwk = ResourceDwk;

    public const string AlgorithmClaim = "alg";
    public const string TypeClaim = "typ";
    public const string KeyIdClaim = "kid";
    public const string IssuerClaim = "iss";
    public const string DomainKeyClaim = "dwk";
    public const string SubjectClaim = "sub";
    public const string AudienceClaim = "aud";
    public const string ConfirmationClaim = "cnf";
    public const string JwkClaim = "jwk";
    public const string EventIdClaim = "eid";
    public const string IssuedAtClaim = "iat";
    public const string ExpiresAtClaim = "exp";
    public const string MaxUsesClaim = "max_uses";
    public const string TokenIdClaim = "jti";
    public const string EIdClaim = EventIdClaim;
    public const string JtiClaim = TokenIdClaim;

    public const string MethodComponent = "@method";
    public const string AuthorityComponent = "@authority";
    public const string PathComponent = "@path";
    public const string SignatureKeyComponent = "signature-key";
    public const string ContentTypeComponent = "content-type";
    public const string ContentDigestComponent = "content-digest";

    public const string EventEndpointMetadata = "event_endpoint";
    public const string EventEndpoint = EventEndpointMetadata;
    public const string AsyncApiVocabulary = "urn:aauth:vocabulary:asyncapi";
    public const string AsyncApiVocabularyKey = AsyncApiVocabulary;
    public const string SubscribeSecurityScheme = "aauth_subscribe";
    public const string SubscribeSecuritySchemeType = "http";
    public const string SubscribeSecuritySchemeName = "aauth-subscribe";
    public const string AsyncApiSubscribeSecurityScheme = SubscribeSecurityScheme;

    public const string JsonMediaType = "application/json";
    public const string JwtMediaType = "application/jwt";
    public const string SubscribeTokenMediaType = "application/jwt";
    public const string EventTokenMediaType = "application/jwt";

    /// <summary>The four components covered by every Events HTTP signature.</summary>
    public static IReadOnlyList<string> BaseHttpComponents { get; } =
        new[] { MethodComponent, AuthorityComponent, PathComponent, SignatureKeyComponent };
    public static IReadOnlyList<string> BaseComponents => BaseHttpComponents;

    /// <summary>Components added for a JSON subscription registration body.</summary>
    public static IReadOnlyList<string> RegistrationAdditionalHttpComponents { get; } =
        new[] { ContentTypeComponent };
    public static IReadOnlyList<string> RegistrationAdditionalComponents => RegistrationAdditionalHttpComponents;

    /// <summary>Components added for a JSON event-delivery body.</summary>
    public static IReadOnlyList<string> EventAdditionalHttpComponents { get; } =
        new[] { ContentTypeComponent, ContentDigestComponent };
    public static IReadOnlyList<string> EventAdditionalComponents => EventAdditionalHttpComponents;

    /// <summary>All components covered by a bodyless Events request.</summary>
    public static IReadOnlyList<string> BodylessHttpComponents => BaseHttpComponents;
}

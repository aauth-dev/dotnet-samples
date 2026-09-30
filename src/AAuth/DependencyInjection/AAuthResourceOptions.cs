using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.HttpSig;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth;

/// <summary>
/// Options for configuring an AAuth resource server via
/// <see cref="AAuthResourceServiceCollectionExtensions.AddAAuthResource"/>.
/// </summary>
public sealed class AAuthResourceOptions
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; set; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    /// <summary>HTTPS issuer URL for this resource (used in metadata and token audience).</summary>
    public string Issuer { get; set; } = null!;

    /// <summary>
    /// Signing keys keyed by <c>kid</c>. These are served via the JWKS endpoint
    /// and used to sign resource tokens / challenges.
    /// </summary>
    public AAuthSigningKeySet SigningKeys { get; set; } = new();

    /// <summary>
    /// A handle in the registered <see cref="IKeyStore"/> to load the signing key from when
    /// <see cref="SigningKeys"/> is empty.
    /// </summary>
    public string? KeyHandle { get; set; }

    /// <summary>The <c>kid</c> for the key loaded from <see cref="KeyHandle"/> (default: its thumbprint).</summary>
    public string? KeyId { get; set; }

    /// <summary>
    /// Signature validity window for inbound <c>created</c>, applied in both
    /// directions. Default: 60 seconds.
    /// </summary>
    public TimeSpan MaxSignatureAge { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Time source for signature and token checks.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// Enable request replay detection using the signing-key thumbprint and
    /// canonical signature base. Default: true. Token revocation is separately
    /// keyed by issuer and token id; reusable tokens are not made single-use.
    /// </summary>
    public bool EnableReplayDetection { get; set; } = true;

    /// <summary>
    /// Enable the resource-managed (two-party) <c>AAuth-Access</c> opaque-token
    /// flow (§Resource-Managed Authorization). When <see langword="true"/>, a
    /// default <see cref="Server.IOpaqueTokenStore"/>
    /// (<see cref="Server.InMemoryOpaqueTokenStore"/>) is registered unless the
    /// app already registered one. The resource's endpoints drive the flow via
    /// the <c>HttpContext</c> resource-managed helpers. Default: false.
    /// </summary>
    public bool EnableResourceManagedAccess { get; set; }

    /// <summary>
    /// Custom <see cref="ISignatureKeyResolver"/>. When null, <see cref="DefaultSignatureKeyResolver"/>
    /// is used with a <see cref="Discovery.JwksClient"/> registered via DI.
    /// </summary>
    public ISignatureKeyResolver? KeyResolver { get; set; }



    /// <summary>Optional human-readable resource name for metadata.</summary>
    public string? Name { get; set; }

    /// <summary>Optional Markdown description for metadata (consent display).</summary>
    public string? Description { get; set; }

    /// <summary>Optional logo URL for metadata (<c>logo_uri</c>).</summary>
    public string? LogoUri { get; set; }

    /// <summary>Optional dark-mode logo URL for metadata (<c>logo_dark_uri</c>).</summary>
    public string? LogoDarkUri { get; set; }

    /// <summary>Optional documentation URL for metadata (<c>documentation_uri</c>).</summary>
    public string? DocumentationUri { get; set; }

    /// <summary>Optional terms-of-service URL for metadata (<c>tos_uri</c>).</summary>
    public string? TosUri { get; set; }

    /// <summary>Optional policy URL for metadata (<c>policy_uri</c>).</summary>
    public string? PolicyUri { get; set; }

    /// <summary>Optional scope descriptions for metadata.</summary>
    public Dictionary<string, string>? ScopeDescriptions { get; set; }

    /// <summary>
    /// Optional signature validity window in seconds (<c>signature_window</c>),
    /// published in resource metadata. Default <c>null</c> (the spec default of
    /// 60 s applies and the value is omitted from the document).
    /// </summary>
    public int? SignatureWindow { get; set; }

    /// <summary>
    /// Optional advisory <c>access_mode</c> published in resource metadata: one
    /// of <c>agent-token</c>, <c>person-token</c>, <c>session-token</c>, <c>auth-token</c>,
    /// or R3's <c>per-call</c>.
    /// </summary>
    public string? AccessMode { get; set; }

    /// <summary>
    /// Optional resource-owned <c>authorization_endpoint</c> URL for proactive
    /// authorization, published in resource metadata. This does not select the
    /// PS/AS resource-token recipient; use <see cref="Server.Challenge.ChallengeOptions.AccessServer"/>.
    /// When absent, the resource issues challenges for authorization instead.
    /// </summary>
    public string? AuthorizationEndpoint { get; set; }

    /// <summary>
    /// Optional <c>revocation_endpoint</c> URL, published in resource metadata. Map it with
    /// <c>app.MapAAuthResourceRevocation()</c>.
    /// </summary>
    public string? RevocationEndpoint { get; set; }

    /// <summary>
    /// Adjusts the revocation endpoint mapped by <c>MapAAuthResourceRevocation</c>. It accepts any
    /// verified issuer unless this narrows <see cref="AAuth.Server.AAuthRevocationOptions.IsAcceptedIssuer"/>.
    /// </summary>
    public Action<AAuth.Server.AAuthRevocationOptions>? ConfigureRevocation { get; set; }

    /// <summary>
    /// Optional extension metadata merged verbatim into the resource well-known
    /// document as top-level members (for example an R3 resource's
    /// <c>r3_vocabularies</c> map). See
    /// <see cref="Server.Metadata.AAuthResourceMetadataOptions.AdditionalMetadata"/>.
    /// </summary>
    public Dictionary<string, JsonNode?>? AdditionalMetadata { get; set; }
}

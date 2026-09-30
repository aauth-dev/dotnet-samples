namespace AAuth;

/// <summary>Well-known protocol constants for the AAuth SDK.</summary>
public static class AAuthConstants
{
    /// <summary>HTTP header names used by AAuth.</summary>
    public static class Headers
    {
        /// <summary>RFC 9421 HTTP signature header.</summary>
        public const string Signature = "Signature";

        /// <summary>RFC 9421 HTTP signature input header.</summary>
        public const string SignatureInput = "Signature-Input";

        /// <summary>AAuth Signature-Key header.</summary>
        public const string SignatureKey = "Signature-Key";

        /// <summary>AAuth error response header.</summary>
        public const string AAuthError = "AAuth-Error";

        /// <summary>AAuth requirement challenge header.</summary>
        public const string AAuthRequirement = "AAuth-Requirement";

        /// <summary>AAuth capabilities header.</summary>
        public const string AAuthCapabilities = "AAuth-Capabilities";

        /// <summary>
        /// AAuth opaque access-token response header (§AAuth-Access Response
        /// Header). Carries a <c>token68</c> the agent replays as
        /// <c>Authorization: AAuth &lt;token68&gt;</c>.
        /// </summary>
        public const string AAuthAccess = "AAuth-Access";
    }

    /// <summary>Signature-Key scheme identifiers.</summary>
    public static class Schemes
    {
        /// <summary>JWT-based agent identity (three-party).</summary>
        public const string Jwt = "jwt";

        /// <summary>Hardware-bound key (pseudonymous).</summary>
        public const string Hwk = "hwk";

        /// <summary>JKT-JWT key delegation (pseudonymous with naming JWT).</summary>
        public const string JktJwt = "jkt-jwt";

        /// <summary>JWKS URI-based agent identity.</summary>
        public const string JwksUri = "jwks_uri";
        public const string Jwks = "jwks";
        public const string SelfJwt = "self-jwt";
    }

    /// <summary>
    /// Resource <c>access_mode</c> metadata values (§Resource Metadata). Advisory
    /// declaration of the credential flow an agent should expect; the runtime
    /// <c>AAuth-Requirement</c> remains authoritative. Distinct from the server-side
    /// <see cref="AAuth.Server.Verification.AAuthAccessMode"/> challenge enum.
    /// </summary>
    public static class AccessModes
    {
        /// <summary>Identity-only: the agent signs with its agent token.</summary>
        public const string AgentToken = "agent-token";

        /// <summary>Person identity: the agent presents a person token from its PS.</summary>
        public const string PersonToken = "person-token";

        /// <summary>Resource-managed: the agent completes the resource's interaction/
        /// consent flow and receives an opaque token via <c>AAuth-Access</c>.</summary>
        public const string SessionToken = "session-token";

        /// <summary>The agent presents a person token first, then an auth token from its PS or the resource's AS.</summary>
        public const string AuthToken = "auth-token";

        /// <summary>R3 extension value: each invocation is authorized individually from a per-call proposal.</summary>
        public const string PerCall = "per-call";
    }

    /// <summary>Metadata member names defined by the AAuth protocol.</summary>
    public static class MetadataFields
    {
        /// <summary>
        /// Resource metadata field listing extra HTTP signature covered components.
        /// </summary>
        public const string AdditionalSignatureComponents = "additional_signature_components";
    }

    /// <summary>
    /// Mission termination reasons (#mission-management). The set is open: a recipient
    /// that does not recognize a reason keeps the <c>terminated</c> state and treats the
    /// reason as an opaque audit value, so reasons stay plain strings.
    /// </summary>
    public static class MissionTerminationReasons
    {
        /// <summary>The person accepted the agent's completion proposal.</summary>
        public const string Completed = "completed";

        /// <summary>The person, the owning agent, or an authorized administrator withdrew the mission.</summary>
        public const string Revoked = "revoked";

        /// <summary>The mission reached its <c>expires_at</c>.</summary>
        public const string Expired = "expired";

        /// <summary>Another approved mission replaced this one.</summary>
        public const string Superseded = "superseded";

        /// <summary>An authorized administrator ended the mission under local policy.</summary>
        public const string Administrative = "administrative";
    }

    /// <summary>Token type (<c>typ</c> header) values.</summary>
    public static class TokenTypes
    {
        /// <summary>Agent token type.</summary>
        public const string AgentToken = "aa-agent+jwt";

        /// <summary>Auth token type.</summary>
        public const string AuthToken = "aa-auth+jwt";

        /// <summary>Person token type.</summary>
        public const string PersonToken = "aa-person+jwt";

        /// <summary>Resource token type.</summary>
        public const string ResourceToken = "aa-resource+jwt";

        /// <summary>
        /// Self-issued <c>jkt-jwt</c> delegation JWT type (SHA-256 thumbprint), per
        /// <c>draft-hardt-httpbis-signature-key-05</c> §3.4 Table 1.
        /// </summary>
        public const string JktS256Jwt = "jkt-s256+jwt";
    }

    /// <summary>
    /// JWK Thumbprint URI prefix for the SHA-256 <c>jkt-jwt</c> issuer claim
    /// (<c>urn:jkt:sha-256:&lt;thumbprint&gt;</c>), per
    /// <c>draft-hardt-httpbis-signature-key-05</c> §3.4 Table 1.
    /// </summary>
    public const string JktThumbprintUrnPrefix = "urn:jkt:sha-256:";

    /// <summary>Well-known DWK file names.</summary>
    public static class DwkFiles
    {
        /// <summary>Agent DWK metadata file.</summary>
        public const string Agent = "aauth-agent.json";

        /// <summary>Person Server DWK metadata file.</summary>
        public const string Person = "aauth-person.json";

        /// <summary>Access Server DWK metadata file.</summary>
        public const string Access = "aauth-access.json";

        /// <summary>Resource DWK metadata file.</summary>
        public const string Resource = "aauth-resource.json";
    }
}

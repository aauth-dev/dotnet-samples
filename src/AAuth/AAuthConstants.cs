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

        /// <summary>AAuth mission header.</summary>
        public const string AAuthMission = "AAuth-Mission";

        /// <summary>AAuth capabilities header.</summary>
        public const string AAuthCapabilities = "AAuth-Capabilities";
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
    }

    /// <summary>Token type (<c>typ</c> header) values.</summary>
    public static class TokenTypes
    {
        /// <summary>Agent token type.</summary>
        public const string AgentToken = "aa-agent+jwt";

        /// <summary>Auth token type.</summary>
        public const string AuthToken = "aa-auth+jwt";

        /// <summary>Resource token type.</summary>
        public const string ResourceToken = "aa-resource+jwt";

        /// <summary>Naming JWT type (key delegation).</summary>
        public const string NamingJwt = "naming+jwt";
    }

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

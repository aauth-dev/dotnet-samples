using System.Text.Json.Nodes;
using AAuth.Discovery;
using AAuth.R3.Model;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.R3;

/// <summary>Builds R3 claims for resource and auth token payloads.</summary>
public static class R3AuthClaims
{
    public const string UriClaim = "r3_uri";
    public const string S256Claim = "r3_s256";
    public const string GrantedClaim = "r3_granted";
    public const string PerCallClaim = "r3_per_call";

    public static IReadOnlyDictionary<string, JsonNode?> ResourceDocument(string r3Uri, string r3S256)
    {
        ValidatePair(r3Uri, r3S256);
        return ResourceDocumentCore(r3Uri, r3S256);
    }

    internal static IReadOnlyDictionary<string, JsonNode?> ResourceDocument(string r3Uri, string r3S256, AAuthEgressPolicy egressPolicy)
    {
        ValidatePair(r3Uri, r3S256, egressPolicy);
        return ResourceDocumentCore(r3Uri, r3S256);
    }

    private static IReadOnlyDictionary<string, JsonNode?> ResourceDocumentCore(string r3Uri, string r3S256)
    {
        return new Dictionary<string, JsonNode?>(StringComparer.Ordinal)
        {
            [UriClaim] = r3Uri,
            [S256Claim] = r3S256,
        };
    }

    public static IReadOnlyDictionary<string, JsonNode?> AuthToken(
        string r3Uri,
        string r3S256,
        R3Grant granted,
        R3Grant? perCall = null,
        R3VocabularySchemas? schemas = null)
    {
        ValidatePair(r3Uri, r3S256);
            return AuthTokenCore(r3Uri, r3S256, granted, perCall, schemas);
        }

        internal static IReadOnlyDictionary<string, JsonNode?> AuthToken(
            string r3Uri,
            string r3S256,
            R3Grant granted,
            R3Grant? perCall,
            R3VocabularySchemas? schemas,
            AAuthEgressPolicy egressPolicy)
        {
            ValidatePair(r3Uri, r3S256, egressPolicy);
            return AuthTokenCore(r3Uri, r3S256, granted, perCall, schemas);
        }

        private static IReadOnlyDictionary<string, JsonNode?> AuthTokenCore(
            string r3Uri,
            string r3S256,
            R3Grant granted,
            R3Grant? perCall,
            R3VocabularySchemas? schemas)
        {
            granted.Validate(allowEmpty: true, schemas);
            perCall?.Validate(allowEmpty: true, schemas);
            if (perCall is not null && perCall.Vocabulary != granted.Vocabulary)
            throw new InvalidOperationException("R3 granted and per-call vocabularies must match.");

        var claims = new Dictionary<string, JsonNode?>(StringComparer.Ordinal)
        {
            [UriClaim] = r3Uri,
            [S256Claim] = r3S256,
            [GrantedClaim] = R3ClaimJson.GrantToJson(granted),
        };
        if (perCall is not null)
        {
            claims[PerCallClaim] = R3ClaimJson.GrantToJson(perCall);
        }
        return claims;
    }

    public static void ValidateResourcePair(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.ContainsKey(UriClaim) && !payload.ContainsKey(S256Claim)) return;
        if (payload[UriClaim] is not JsonValue uriValue || !uriValue.TryGetValue<string>(out var uri)
            || payload[S256Claim] is not JsonValue hashValue || !hashValue.TryGetValue<string>(out var s256))
        {
            throw new InvalidOperationException("r3_uri and r3_s256 must be present together as strings.");
        }
        ValidatePair(uri, s256);
    }

    internal static void ValidateResourcePair(JsonObject payload, AAuthEgressPolicy egressPolicy)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.ContainsKey(UriClaim) && !payload.ContainsKey(S256Claim)) return;
        if (payload[UriClaim] is not JsonValue uriValue || !uriValue.TryGetValue<string>(out var uri)
            || payload[S256Claim] is not JsonValue hashValue || !hashValue.TryGetValue<string>(out var s256))
        {
            throw new InvalidOperationException("r3_uri and r3_s256 must be present together as strings.");
        }
        ValidatePair(uri, s256, egressPolicy);
    }

    private static void ValidatePair(string r3Uri, string r3S256, AAuthEgressPolicy? egressPolicy = null)
    {
        if (string.IsNullOrWhiteSpace(r3Uri))
        {
            throw new InvalidOperationException("r3_uri must be set.");
        }
        if (!Uri.TryCreate(r3Uri, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException("r3_uri must be an absolute URI.");
        }
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            && (egressPolicy is null || !AAuthUrl.IsHttpsOrLoopback(uri.GetLeftPart(UriPartial.Authority), egressPolicy)))
        {
            throw new InvalidOperationException("r3_uri must use https.");
        }
        if (string.IsNullOrWhiteSpace(r3S256))
        {
            throw new InvalidOperationException("r3_s256 must be set.");
        }
        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(r3S256);
            if (bytes.Length != 32 || Base64UrlEncoder.Encode(bytes) != r3S256)
                throw new FormatException();
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("r3_s256 must be an unpadded base64url SHA-256 digest.", ex);
        }
    }
}

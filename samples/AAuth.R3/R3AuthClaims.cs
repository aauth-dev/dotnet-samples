using System.Text.Json.Nodes;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Builds R3 claims for resource and auth token payloads.</summary>
public static class R3AuthClaims
{
    public const string UriClaim = "r3_uri";
    public const string S256Claim = "r3_s256";
    public const string GrantedClaim = "r3_granted";
    public const string ConditionalClaim = "r3_conditional";

    public static IReadOnlyDictionary<string, JsonNode?> ResourceDocument(string r3Uri, string r3S256)
    {
        ValidatePair(r3Uri, r3S256);
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
        R3Grant? conditional = null)
    {
        ValidatePair(r3Uri, r3S256);
        granted.Validate(allowEmpty: true);
        conditional?.Validate(allowEmpty: true);

        var claims = new Dictionary<string, JsonNode?>(StringComparer.Ordinal)
        {
            [UriClaim] = r3Uri,
            [S256Claim] = r3S256,
            [GrantedClaim] = R3ClaimJson.GrantToJson(granted),
        };
        if (conditional is not null)
        {
            claims[ConditionalClaim] = R3ClaimJson.GrantToJson(conditional);
        }
        return claims;
    }

    public static void ValidateResourcePair(JsonObject payload)
    {
        var uri = (string?)payload[UriClaim];
        var s256 = (string?)payload[S256Claim];
        if ((uri is null) != (s256 is null))
        {
            throw new InvalidOperationException("r3_uri and r3_s256 must be present together.");
        }
        if (uri is not null)
        {
            ValidatePair(uri, s256!);
        }
    }

    private static void ValidatePair(string r3Uri, string r3S256)
    {
        if (string.IsNullOrWhiteSpace(r3Uri))
        {
            throw new InvalidOperationException("r3_uri must be set.");
        }
        if (!Uri.TryCreate(r3Uri, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException("r3_uri must be an absolute URI.");
        }
        if (string.IsNullOrWhiteSpace(r3S256))
        {
            throw new InvalidOperationException("r3_s256 must be set.");
        }
    }
}

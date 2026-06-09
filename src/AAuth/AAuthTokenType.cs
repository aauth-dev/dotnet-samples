namespace AAuth;

/// <summary>AAuth token types from the JWT <c>typ</c> header.</summary>
public enum AAuthTokenType
{
    /// <summary>Unknown or missing token type.</summary>
    Unknown = 0,

    /// <summary>Agent token (<c>aa-agent+jwt</c>).</summary>
    AgentToken,

    /// <summary>Auth token (<c>aa-auth+jwt</c>).</summary>
    AuthToken,

    /// <summary>Resource token (<c>aa-resource+jwt</c>).</summary>
    ResourceToken,

    /// <summary>Self-issued <c>jkt-jwt</c> key-delegation JWT (<c>jkt-s256+jwt</c>).</summary>
    JktS256Jwt,
}

/// <summary>Extension methods for <see cref="AAuthTokenType"/>.</summary>
public static class AAuthTokenTypeExtensions
{
    /// <summary>Convert the enum to its JWT <c>typ</c> header string value.</summary>
    public static string ToHeaderValue(this AAuthTokenType type) => type switch
    {
        AAuthTokenType.AgentToken => AAuthConstants.TokenTypes.AgentToken,
        AAuthTokenType.AuthToken => AAuthConstants.TokenTypes.AuthToken,
        AAuthTokenType.ResourceToken => AAuthConstants.TokenTypes.ResourceToken,
        AAuthTokenType.JktS256Jwt => AAuthConstants.TokenTypes.JktS256Jwt,
        _ => throw new System.ArgumentOutOfRangeException(nameof(type), type, "Unknown AAuth token type."),
    };

    /// <summary>Parse a JWT <c>typ</c> header value to the enum.</summary>
    public static AAuthTokenType ParseTokenType(string? typ) => typ switch
    {
        AAuthConstants.TokenTypes.AgentToken => AAuthTokenType.AgentToken,
        AAuthConstants.TokenTypes.AuthToken => AAuthTokenType.AuthToken,
        AAuthConstants.TokenTypes.ResourceToken => AAuthTokenType.ResourceToken,
        AAuthConstants.TokenTypes.JktS256Jwt => AAuthTokenType.JktS256Jwt,
        _ => AAuthTokenType.Unknown,
    };
}

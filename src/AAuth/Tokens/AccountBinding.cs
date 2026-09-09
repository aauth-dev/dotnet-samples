using System;
using System.Text.Json.Nodes;

namespace AAuth.Tokens;

public sealed record AccountExpectation
{
    public AccountExpectation(string? account)
    {
        AccountBinding.Validate(account);
        Account = account;
    }

    public string? Account { get; }
}

public static class AccountBinding
{
    public static string? Read(JsonObject? payload) => payload is null ? null
        : TryRead(payload, out var account) ? account
        : throw new TokenVerificationException("Account must be a non-empty string without control characters.");

    public static bool IsValid(string? account) => account is null ||
        (!string.IsNullOrWhiteSpace(account) && !ContainsControl(account));

    public static void Validate(string? account)
    {
        if (!IsValid(account))
            throw new ArgumentException("Account must be a non-empty opaque string without control characters.", nameof(account));
    }

    public static bool TryRead(JsonObject payload, out string? account)
    {
        account = null;
        if (!payload.TryGetPropertyValue("account", out var node)) return true;
        return node is JsonValue value && value.TryGetValue(out account) && account is not null && IsValid(account);
    }

    public static bool Matches(string? expected, string? actual) =>
        string.Equals(expected, actual, StringComparison.Ordinal);

    private static bool ContainsControl(string account)
    {
        foreach (var character in account)
            if (char.IsControl(character)) return true;
        return false;
    }
}
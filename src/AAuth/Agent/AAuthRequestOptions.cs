using System.Net.Http;
using AAuth.Tokens;

namespace AAuth.Agent;

public static class AAuthRequestOptions
{
    public static readonly HttpRequestOptionsKey<string> Account = new("AAuth.Account");
    public static readonly HttpRequestOptionsKey<string> ResourceIdentifier = new("AAuth.ResourceIdentifier");
    public static readonly HttpRequestOptionsKey<string> PresentedToken = new("AAuth.PresentedToken");

    public static string? GetAccount(HttpRequestMessage request)
    {
        request.Options.TryGetValue(Account, out var account);
        AccountBinding.Validate(account);
        return account;
    }
}
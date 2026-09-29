using System.Net.Http;
using AAuth.Tokens;

namespace AAuth.Agent;

public static class AAuthRequestOptions
{
    public static readonly HttpRequestOptionsKey<string> Account = new("AAuth.Account");
    public static readonly HttpRequestOptionsKey<string> ResourceIdentifier = new("AAuth.ResourceIdentifier");
    public static readonly HttpRequestOptionsKey<string> PresentedToken = new("AAuth.PresentedToken");

    /// <summary>The mission to request person tokens under for this request (<c>mission_s256</c>).</summary>
    public static readonly HttpRequestOptionsKey<string> MissionS256 = new("AAuth.MissionS256");

    /// <summary>Person tokens the PS issued with the mission approval, keyed by resource (<see cref="Mission.PersonTokens"/>).</summary>
    public static readonly HttpRequestOptionsKey<System.Collections.Generic.IReadOnlyDictionary<string, string>> MissionPersonTokens =
        new("AAuth.MissionPersonTokens");

    public static string? GetMissionS256(HttpRequestMessage request)
        => request.Options.TryGetValue(MissionS256, out var mission) ? mission : null;

    public static string? GetAccount(HttpRequestMessage request)
    {
        request.Options.TryGetValue(Account, out var account);
        AccountBinding.Validate(account);
        return account;
    }
}
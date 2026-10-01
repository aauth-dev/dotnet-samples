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

    /// <summary>Per-request interaction handler; beats the agent's configured handler (for example, the current user's session).</summary>
    public static readonly HttpRequestOptionsKey<IAAuthInteractionHandler> InteractionHandler = new("AAuth.InteractionHandler");

    /// <summary>Per-request clarification handler; beats the agent's configured handler.</summary>
    public static readonly HttpRequestOptionsKey<IAAuthClarificationHandler> ClarificationHandler = new("AAuth.ClarificationHandler");

    /// <summary>Per-request deferred-response observer; beats the agent's configured observer.</summary>
    public static readonly HttpRequestOptionsKey<IAAuthDeferredObserver> DeferredObserver = new("AAuth.DeferredObserver");

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
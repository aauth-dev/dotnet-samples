using AAuth;
using AAuth.Agent;
using Microsoft.Extensions.Options;

namespace SampleApp;

/// <summary>The agents SampleApp registers with <c>AddAAuthAgent</c>.</summary>
public sealed class SampleAgents(IHttpClientFactory clients, IOptionsMonitor<AAuthAgentOptions> options,
    IServiceProvider services)
{
    /// <summary>Aria, the self-issued travel assistant (<c>AAuth:Agents:aria</c>).</summary>
    public const string Aria = "aria";

    /// <summary>Aria's signed, challenge-handling client. Shared by every page.</summary>
    public HttpClient AriaClient => clients.CreateClient(Aria);

    /// <summary>Aria's Person Server, from its registration.</summary>
    public string PersonServer => options.Get(Aria).PersonServer!;

    /// <summary>
    /// Aria's configured Person Server polling budget (<c>Challenge</c>), for typed clients that
    /// take per-call options, such as <c>GovernanceOptions.PollerOptions</c>.
    /// </summary>
    public DeferredPollerOptions PollerOptions
    {
        get
        {
            var challenge = options.Get(Aria).Challenge;
            return new() { MaxTotalWait = challenge.PollingTimeout, DefaultPollInterval = challenge.DefaultPollInterval };
        }
    }

    /// <summary>
    /// Demo only: forget Aria's person and auth tokens so the next run asks for consent again.
    /// A real agent keeps them until they expire or the person signs out.
    /// </summary>
    public void StartOver() => services.GetRequiredKeyedService<IAAuthTokenCache>(Aria).Clear();
}

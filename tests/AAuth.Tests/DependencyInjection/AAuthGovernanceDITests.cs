using System.Linq;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Server.Governance;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.DependencyInjection;

/// <summary>
/// Unit tests for <c>AddAAuthGovernance</c> (§PS Governance Endpoints): the call
/// registers in-memory storage seams plus conservative default policy/user-channel
/// seams, all via <c>TryAdd</c> so a PS overrides only what it needs.
/// </summary>
public class AAuthGovernanceDITests
{
    [Fact]
    public void AddAAuthGovernance_RegistersStorageAndDefaultSeams()
    {
        var services = new ServiceCollection();
        services.AddAAuthGovernance();
        var provider = services.BuildServiceProvider();

        Assert.IsType<InMemoryMissionStore>(provider.GetRequiredService<IMissionStore>());
        Assert.IsType<InMemoryMissionLog>(provider.GetRequiredService<IMissionLog>());
        Assert.IsType<DefaultPermissionDecider>(provider.GetRequiredService<IPermissionDecider>());
        Assert.IsType<DefaultAuditSink>(provider.GetRequiredService<IAuditSink>());
        Assert.IsType<DefaultInteractionRelay>(provider.GetRequiredService<IInteractionRelay>());
    }

    [Fact]
    public void AddAAuthGovernance_DoesNotOverrideCustomSeams()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPermissionDecider, CustomDecider>();
        services.AddAAuthGovernance();
        var provider = services.BuildServiceProvider();

        Assert.IsType<CustomDecider>(provider.GetRequiredService<IPermissionDecider>());
    }

    [Fact]
    public async Task DefaultPermissionDecider_PromptsForUnknownAction()
    {
        var decider = new DefaultPermissionDecider();
        var context = new PermissionDecisionContext(
            new PermissionRequest(new MissionAction("SendEmail")), Mission: null, Log: System.Array.Empty<MissionLogEntry>());

        var decision = await decider.DecideAsync(context);

        Assert.Equal(PermissionOutcome.Prompt, decision.Outcome);
        Assert.Equal(PermissionDecisionReason.OutOfScope, decision.Reason);
    }

    [Fact]
    public async Task DefaultInteractionRelay_HasNoUserChannel()
    {
        var relay = new DefaultInteractionRelay();

        var question = await relay.RelayAsync(new InteractionRequest(InteractionType.Question));
        Assert.Equal(string.Empty, question.Answer);

        var completion = await relay.RelayAsync(new InteractionRequest(InteractionType.Completion));
        Assert.False(completion.Accepted);
    }

    private sealed class CustomDecider : IPermissionDecider
    {
        public Task<PermissionDecision> DecideAsync(PermissionDecisionContext context, System.Threading.CancellationToken ct = default)
            => Task.FromResult(new PermissionDecision(PermissionOutcome.Denied, PermissionDecisionReason.OutOfScope));
    }
}

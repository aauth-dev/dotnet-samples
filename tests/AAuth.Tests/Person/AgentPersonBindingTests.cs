using AAuth.Person;
using AAuth.Server;

namespace AAuth.Tests.Person;

public class AgentPersonBindingTests
{
    [Fact]
    public async Task RevokeAsync_RevokeInventoryBeforeBindingStore()
    {
        var bindingStore = new InMemoryAgentPersonBindingStore();
        var context = new AgentPersonBindingContext(
            "https://ps.example",
            "https://ap.example",
            "aauth:agent@example",
            new AAuthPersonKey("person-1"));
        var original = await bindingStore.BindOrVerifyAsync(context);
        Assert.NotNull(original);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AgentPersonBinding.RevokeAsync(new ThrowingRevokeInventory(), bindingStore,
                context.PersonServer, context.AgentIssuer, context.AgentId));

        Assert.Equal("inventory unavailable", failure.Message);
        Assert.Null(await bindingStore.BindOrVerifyAsync(context with { PersonKey = new AAuthPersonKey("person-2") }));
        var stillBound = await bindingStore.BindOrVerifyAsync(context);
        Assert.Equal(original, stillBound);
    }

    private sealed class ThrowingRevokeInventory : IJtiStore
    {
        public Task<bool> TryRecordRequestAsync(string requestKey, DateTimeOffset expiration, CancellationToken ct = default)
            => Task.FromResult(true);

        public Task<bool> RegisterAsync(TokenKey token, DateTimeOffset expiration, CancellationToken ct = default)
            => Task.FromResult(true);

        public Task RevokeAsync(TokenKey token, DateTimeOffset expiresAt, CancellationToken ct = default)
            => throw new InvalidOperationException("inventory unavailable");

        public Task<bool> IsRevokedAsync(TokenKey token, CancellationToken ct = default)
            => Task.FromResult(false);

        public Task<bool> ContainsTokenAsync(TokenKey token, CancellationToken ct = default)
            => Task.FromResult(true);

        public Task<bool> RegisterGrantAsync(IReadOnlyCollection<TokenKey> sources, TokenGrant grant, CancellationToken ct = default)
            => Task.FromResult(true);

        public Task<bool> CheckProvenanceQuotaAsync(UpstreamCallerRecord caller, string resource, CancellationToken ct = default)
            => Task.FromResult(true);

        public Task<IReadOnlyList<TokenGrant>> GetGrantsAsync(TokenKey source, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<TokenGrant>>(Array.Empty<TokenGrant>());

        public Task<TokenGrant?> GetGrantAsync(TokenKey token, CancellationToken ct = default)
            => Task.FromResult<TokenGrant?>(null);

        public Task RecordSubjectAsync(TokenKey token, string subject, CancellationToken ct = default)
            => Task.CompletedTask;

        public Task<string?> GetSubjectAsync(TokenKey token, CancellationToken ct = default)
            => Task.FromResult<string?>(null);
    }
}

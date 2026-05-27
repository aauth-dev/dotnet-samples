using System;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using Xunit;

namespace AAuth.Conformance.AgentTokens;

/// <summary>
/// Conformance tests for agent-side bootstrap and key store (§7).
/// </summary>
public class AgentBootstrapTests
{
    [Fact(DisplayName = "§7 — IKeyStore: InMemoryKeyStore stores and retrieves keys")]
    public async Task KeyStore_StoreAndLoad()
    {
        var store = new InMemoryKeyStore();
        var key = AAuth.Crypto.AAuthKey.Generate();
        await store.StoreAsync("test-key", key);
        var loaded = await store.LoadAsync("test-key");
        Assert.NotNull(loaded);
        // Verify it's the same key by signing + verifying
        var data = "test"u8.ToArray();
        var sig = key.Sign(data);
        Assert.True(loaded!.Verify(data, sig));
    }

    [Fact(DisplayName = "§7 — IKeyStore: returns null for unknown keys")]
    public async Task KeyStore_ReturnsNull()
    {
        var store = new InMemoryKeyStore();
        var result = await store.LoadAsync("nonexistent");
        Assert.Null(result);
    }

    [Fact(DisplayName = "§7 — IKeyStore: delete removes key")]
    public async Task KeyStore_DeleteRemovesKey()
    {
        var store = new InMemoryKeyStore();
        var key = AAuth.Crypto.AAuthKey.Generate();
        await store.StoreAsync("del-key", key);
        await store.DeleteAsync("del-key");
        Assert.Null(await store.LoadAsync("del-key"));
    }

    [Fact(DisplayName = "§7 — IKeyStore: list returns stored key ids")]
    public async Task KeyStore_ListReturnsIds()
    {
        var store = new InMemoryKeyStore();
        var key = AAuth.Crypto.AAuthKey.Generate();
        await store.StoreAsync("k1", key);
        await store.StoreAsync("k2", key);
        var ids = await store.ListAsync();
        Assert.Contains("k1", ids);
        Assert.Contains("k2", ids);
    }

    [Fact(DisplayName = "§7 — IPlatformAttestor: NoopAttestor returns empty")]
    public async Task NoopAttestor_ReturnsEmpty()
    {
        var attestor = new NoopAttestor();
        var result = await attestor.AttestAsync("challenge");
        Assert.Equal(string.Empty, result);
    }
}

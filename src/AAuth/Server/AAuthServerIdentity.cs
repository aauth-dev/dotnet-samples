using System.Diagnostics.CodeAnalysis;
using AAuth.Access;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Person;
using AAuth.Server.Governance;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AAuth.Server;

/// <summary>
/// The identity of a registered Person Server or Access Server instance: its issuer
/// and signing keys, held once. Resolve it as a keyed service by instance name
/// (<c>GetRequiredKeyedService&lt;IAAuthServerIdentity&gt;(name)</c>). It signs through
/// the key set's active <see cref="IAAuthSigner"/> and never exposes a raw key.
/// </summary>
public interface IAAuthServerIdentity
{
    /// <summary>The role instance name it was registered under.</summary>
    string Name { get; }

    /// <summary>The issuer identifier (<c>iss</c> of tokens this server mints).</summary>
    string Issuer { get; }

    /// <summary>The well-known document name for this role, e.g. <c>aauth-person.json</c>.</summary>
    string Dwk { get; }

    /// <summary>The published signing keys; tokens are signed with the active key.</summary>
    AAuthSigningKeySet SigningKeys { get; }

    /// <summary>The egress policy for outbound calls made as this server.</summary>
    AAuthEgressPolicy EgressPolicy { get; }

    /// <summary>An absolute URL on this server for <paramref name="path"/>.</summary>
    string Url(string path);

    /// <summary>
    /// An <see cref="HttpClient"/> that signs every request as this server (<c>jwks_uri</c>
    /// scheme, active key). Pass <paramref name="innerHandler"/> and its
    /// <paramref name="transportContract"/> to route the transport, for example in process.
    /// </summary>
    HttpClient CreateSignedClient(HttpMessageHandler? innerHandler = null, AAuthTransportContract? transportContract = null);
}

internal sealed class AAuthServerIdentity(string name, string issuer, string dwk, AAuthSigningKeySet signingKeys,
    AAuthEgressPolicy egressPolicy) : IAAuthServerIdentity
{
    public string Name { get; } = name;
    public string Issuer { get; } = issuer;
    public string Dwk { get; } = dwk;
    public AAuthSigningKeySet SigningKeys { get; } = signingKeys;
    public AAuthEgressPolicy EgressPolicy { get; } = egressPolicy;

    public string Url(string path) => AAuthServerRoles.Url(Issuer, path);

    public HttpClient CreateSignedClient(HttpMessageHandler? innerHandler = null, AAuthTransportContract? transportContract = null)
    {
        if (innerHandler is not null && transportContract is null)
            throw new ArgumentException("A custom inner handler requires its transport contract.", nameof(transportContract));
        var signing = new AAuthSigningKeySetHandler(SigningKeys, Issuer, Dwk)
        {
            InnerHandler = innerHandler ?? AAuthHttpTransport.CreateHandler(EgressPolicy),
        };
        return AAuthHttpTransport.AttachPolicy(new HttpClient(signing), EgressPolicy,
            transportContract ?? AAuthTransportContract.EnforcesEgressPolicy);
    }
}

internal static class AAuthServerRoles
{
    public static string Url(string issuer, string path) => issuer.TrimEnd('/') + "/" + path.TrimStart('/');

    /// <summary>Replace any keyed registration of the same service and key (a builder <c>Use*</c> helper).</summary>
    public static void ReplaceKeyed(IServiceCollection services, ServiceDescriptor descriptor)
    {
        for (var i = services.Count - 1; i >= 0; i--)
        {
            if (services[i].IsKeyedService && services[i].ServiceType == descriptor.ServiceType
                && Equals(services[i].ServiceKey, descriptor.ServiceKey))
                services.RemoveAt(i);
        }
        services.Add(descriptor);
    }

    [return: NotNullIfNotNull(nameof(path))]
    public static string? OptionalUrl(string issuer, string? path) => path is null ? null : Url(issuer, path);

    /// <summary>Load <paramref name="keyHandle"/> from the registered <see cref="IKeyStore"/> into an empty key set.</summary>
    public static void LoadKeyHandle(AAuthSigningKeySet keys, string? keyHandle, string? keyId, IServiceProvider services,
        string owner)
    {
        if (keys.Count > 0 || string.IsNullOrEmpty(keyHandle)) return;
        lock (keys)
        {
            if (keys.Count > 0) return;
            var store = services.GetService<IKeyStore>()
                ?? throw new InvalidOperationException($"{owner}.KeyHandle is set but no IKeyStore is registered.");
            // Startup-only: the options pipeline is synchronous.
            var signer = store.LoadAsync(keyHandle).GetAwaiter().GetResult()
                ?? throw new InvalidOperationException($"{owner}.KeyHandle '{keyHandle}' was not found in the key store.");
            keys.Add(string.IsNullOrEmpty(keyId) ? signer.ComputeJwkThumbprint() : keyId, signer);
        }
    }

    /// <summary>Confine a role instance to its issuer's host when <paramref name="matchIssuerHost"/> is set.</summary>
    public static (IEndpointRouteBuilder Routes, Func<HttpContext, bool> InScope) Scope(
        WebApplication app, string issuer, bool matchIssuerHost)
    {
        if (!matchIssuerHost) return (app, static _ => true);
        var authority = new Uri(issuer).Authority;
        var group = app.MapGroup("");
        group.RequireHost(authority);
        return (group, context => string.Equals(context.Request.Host.Value, authority, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Warn when a role instance runs on an in-memory default outside Development: its state
    /// is lost on restart and is not shared across instances.
    /// </summary>
    public static void WarnOnInMemoryDefaults(IServiceProvider services, ILogger logger, string role, string name,
        params object?[] seams)
    {
        var environment = services.GetService<IHostEnvironment>();
        if (environment is null || environment.IsDevelopment()) return;
        foreach (var seam in seams)
        {
            if (seam is InMemoryJtiStore or InMemoryPersonPendingStore or InMemoryAccessPendingStore
                or InMemoryMissionStore or InMemoryMissionLog)
            {
                logger.LogWarning(
                    "{Role} '{Name}' uses the in-memory {Seam} outside Development: its state is lost on restart and not " +
                    "shared across instances. Register a durable implementation.", role, name, seam.GetType().Name);
            }
        }
    }
}

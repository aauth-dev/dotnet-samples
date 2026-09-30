using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AAuth.Events;

public sealed class EventsSignatureTokenVerifier(bool subscribe) : ISignatureTokenVerifier
{
    public string Scheme => subscribe ? "jwt" : "self-jwt";
    public string TokenType => subscribe ? EventsTokens.SubscribeType : EventsTokens.EventType;
    public ValueTask<IAAuthKey?> ResolveIssuerKeyAsync(SignatureTokenIssuerKeyContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IAAuthKey?>(null);
    }

    public Task<TokenVerifier.VerifiedToken> VerifyAsync(SignatureTokenVerificationContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(EventsTokens.Verify(context.Jwt, context.IssuerKey, subscribe, context.TokenVerifier));
    }
}

/// <summary>Options for the <see cref="EventsProtocol"/> registered by <see cref="EventsServiceExtensions.AddAAuthEvents"/>.</summary>
public sealed class AAuthEventsOptions
{
    /// <summary>Egress policy for event discovery and delivery.</summary>
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; set; } = AAuth.Discovery.AAuthEgressPolicy.Production;

    /// <summary>Clock for event token checks.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// Optional inner handler for the protocol's transport (for example an in-process test
    /// server); requires <see cref="TransportContract"/>.
    /// </summary>
    public HttpMessageHandler? InnerHandler { get; set; }

    /// <summary>The contract <see cref="InnerHandler"/> satisfies.</summary>
    public AAuth.Discovery.AAuthTransportContract? TransportContract { get; set; }
}

public static class EventsServiceExtensions
{
    /// <summary>
    /// Register the event token verifiers and a shared <see cref="EventsProtocol"/>. The event
    /// endpoints resolve it, and the app-registered <see cref="IAgentProviderEventStore"/> or
    /// <see cref="IResourceEventStore"/>, from DI.
    /// </summary>
    public static IServiceCollection AddAAuthEvents(this IServiceCollection services, Action<AAuthEventsOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISignatureTokenVerifier, SubscribeVerifier>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISignatureTokenVerifier, EventVerifier>());
        var options = services.AddOptions<AAuthEventsOptions>();
        if (configure is not null) options.Configure(configure);
        services.TryAddSingleton(sp =>
        {
            var value = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AAuthEventsOptions>>().Value;
            if (value.InnerHandler is not null && value.TransportContract is null)
                throw new InvalidOperationException("AAuthEventsOptions.InnerHandler requires TransportContract.");
            var http = AAuth.Discovery.AAuthHttpTransport.AttachPolicy(
                new HttpClient(value.InnerHandler ?? AAuth.Discovery.AAuthHttpTransport.CreateHandler(value.EgressPolicy),
                    disposeHandler: value.InnerHandler is null),
                value.EgressPolicy, value.TransportContract ?? AAuth.Discovery.AAuthTransportContract.EnforcesEgressPolicy);
            return new EventsProtocol(http, sp.GetServices<ISignatureTokenVerifier>(), value.TimeProvider);
        });
        return services;
    }

    private sealed class SubscribeVerifier : ISignatureTokenVerifier
    {
        public string Scheme => "jwt";
        public string TokenType => EventsTokens.SubscribeType;
        public ValueTask<IAAuthKey?> ResolveIssuerKeyAsync(SignatureTokenIssuerKeyContext context, CancellationToken cancellationToken)
            => new EventsSignatureTokenVerifier(true).ResolveIssuerKeyAsync(context, cancellationToken);
        public Task<TokenVerifier.VerifiedToken> VerifyAsync(SignatureTokenVerificationContext context, CancellationToken cancellationToken)
            => new EventsSignatureTokenVerifier(true).VerifyAsync(context, cancellationToken);
    }

    private sealed class EventVerifier : ISignatureTokenVerifier
    {
        public string Scheme => "self-jwt";
        public string TokenType => EventsTokens.EventType;
        public ValueTask<IAAuthKey?> ResolveIssuerKeyAsync(SignatureTokenIssuerKeyContext context, CancellationToken cancellationToken)
            => new EventsSignatureTokenVerifier(false).ResolveIssuerKeyAsync(context, cancellationToken);
        public Task<TokenVerifier.VerifiedToken> VerifyAsync(SignatureTokenVerificationContext context, CancellationToken cancellationToken)
            => new EventsSignatureTokenVerifier(false).VerifyAsync(context, cancellationToken);
    }
}
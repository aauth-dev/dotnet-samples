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
    public Task<TokenVerifier.VerifiedToken> VerifyAsync(string jwt, IAAuthKey issuerKey,
        TokenVerifier verifier, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(EventsTokens.Verify(jwt, issuerKey, subscribe, verifier));
    }
}

public static class EventsServiceExtensions
{
    public static IServiceCollection AddAAuthEvents(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISignatureTokenVerifier, SubscribeVerifier>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISignatureTokenVerifier, EventVerifier>());
        return services;
    }

    private sealed class SubscribeVerifier : ISignatureTokenVerifier
    {
        public string Scheme => "jwt";
        public string TokenType => EventsTokens.SubscribeType;
        public Task<TokenVerifier.VerifiedToken> VerifyAsync(string jwt, IAAuthKey key, TokenVerifier verifier, CancellationToken cancellationToken)
            => new EventsSignatureTokenVerifier(true).VerifyAsync(jwt, key, verifier, cancellationToken);
    }

    private sealed class EventVerifier : ISignatureTokenVerifier
    {
        public string Scheme => "self-jwt";
        public string TokenType => EventsTokens.EventType;
        public Task<TokenVerifier.VerifiedToken> VerifyAsync(string jwt, IAAuthKey key, TokenVerifier verifier, CancellationToken cancellationToken)
            => new EventsSignatureTokenVerifier(false).VerifyAsync(jwt, key, verifier, cancellationToken);
    }
}
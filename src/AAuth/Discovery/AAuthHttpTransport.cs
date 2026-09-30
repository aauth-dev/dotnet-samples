using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Discovery;

/// <summary>Explicit obligations for caller-owned handlers and HTTP clients.</summary>
public enum AAuthTransportContract
{
    /// <summary>The injected transport does no network I/O, including forwarding. Intended for in-process fixtures only.</summary>
    InProcessOnly,
    /// <summary>The caller enforces this policy's DNS/address admission and connection pinning, TLS 1.2-or-later, disables proxies and redirects, and bounds headers and connection time.</summary>
    EnforcesEgressPolicy,
}

/// <summary>Creates pinned transports and bounds admitted requests, including response-body reads.</summary>
public static class AAuthHttpTransport
{
    private sealed record Registration(AAuthEgressPolicy Policy, AAuthTransportContract Contract);
    private static readonly ConditionalWeakTable<HttpClient, Registration> Policies = new();

    public static HttpClient CreateClient(AAuthEgressPolicy? policy = null) =>
        AttachPolicy(new HttpClient(CreateHandler(policy)), policy ?? AAuthEgressPolicy.Production,
            AAuthTransportContract.EnforcesEgressPolicy);

    /// <summary>Declares the caller's security obligations. This does not retrofit DNS pinning or disable redirects on an opaque HttpClient.</summary>
    public static HttpClient AttachPolicy(HttpClient client, AAuthEgressPolicy policy, AAuthTransportContract contract)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(policy);
        if (!Enum.IsDefined(contract)) throw new ArgumentOutOfRangeException(nameof(contract));
        lock (Policies)
        {
            if (Policies.TryGetValue(client, out var existing) && (!ReferenceEquals(existing.Policy, policy) || existing.Contract != contract))
                throw new InvalidOperationException("An HTTP client's egress policy cannot be changed.");
            Policies.GetValue(client, _ => new(policy, contract));
        }
        return client;
    }

    public static AAuthEgressPolicy GetPolicy(HttpClient client) =>
        Policies.TryGetValue(client, out var registration) ? registration.Policy
            : throw new InvalidOperationException("Injected HTTP clients require AAuthHttpTransport.AttachPolicy and an explicit transport contract.");

    public static Task AdmitInteractionAsync(HttpClient client, string url, CancellationToken cancellationToken = default)
    {
        var policy = GetPolicy(client);
        return AdmitInteractionAsync(policy, Policies.GetValue(client, _ => throw new InvalidOperationException()).Contract, url, cancellationToken);
    }

    internal static Task AdmitInteractionAsync(AAuthEgressPolicy policy, AAuthTransportContract contract,
        string url, CancellationToken cancellationToken)
    {
        policy.ValidateUrl(url);
        return contract == AAuthTransportContract.InProcessOnly ? Task.CompletedTask : policy.ValidateDestinationAsync(url, cancellationToken);
    }

    public static HttpMessageHandler CreateHandler(AAuthEgressPolicy? policy = null,
        HttpMessageHandler? innerHandler = null, AAuthTransportContract? contract = null)
    {
        policy ??= AAuthEgressPolicy.Production;
        if (innerHandler is not null && (contract is null || !Enum.IsDefined(contract.Value)))
            throw new ArgumentException("Injected handlers require an explicit transport contract.", nameof(contract));
        return new AdmissionHandler(policy, contract ?? AAuthTransportContract.EnforcesEgressPolicy,
            innerHandler ?? new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseProxy = false,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.None,
                MaxResponseHeadersLength = 32,
                ConnectTimeout = policy.RequestTimeout,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                SslOptions = new() { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 },
                ConnectCallback = async (context, cancellationToken) =>
                {
                    var uri = policy.ValidateUrl(context.InitialRequestMessage.RequestUri!.OriginalString);
                    if (context.DnsEndPoint.Host != uri.IdnHost || context.DnsEndPoint.Port != uri.Port)
                        throw new HttpRequestException("Connection destination differs from admitted request.");
                    var addresses = await policy.ResolveAsync(uri, cancellationToken).ConfigureAwait(false);
                    foreach (var address in addresses)
                    {
                        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                        try
                        {
                            await socket.ConnectAsync(new IPEndPoint(address, uri.Port), cancellationToken).ConfigureAwait(false);
                            if (socket.RemoteEndPoint is not IPEndPoint remote || !remote.Address.Equals(address) || remote.Port != uri.Port)
                                throw new HttpRequestException("Connected peer differs from pinned destination.");
                            return new NetworkStream(socket, ownsSocket: true);
                        }
                        catch (SocketException)
                        {
                            socket.Dispose();
                        }
                        catch
                        {
                            socket.Dispose();
                            throw;
                        }
                    }
                    throw new HttpRequestException("Unable to connect to an admitted destination.");
                },
            });
    }

    internal static HttpMessageHandler? BorrowEnforcingHandler(HttpMessageHandler handler, AAuthEgressPolicy policy)
    {
        var lifetimeOwner = handler;
        while (handler is DelegatingHandler delegating)
        {
            var type = handler.GetType();
            if (type.Assembly != typeof(Microsoft.Extensions.Http.HttpMessageHandlerBuilder).Assembly ||
                type.FullName is not ("Microsoft.Extensions.Http.LifetimeTrackingHttpMessageHandler" or
                    "Microsoft.Extensions.Http.Logging.LoggingHttpMessageHandler" or
                    "Microsoft.Extensions.Http.Logging.LoggingScopeHttpMessageHandler")) return null;
            if (delegating.InnerHandler is null) return null;
            handler = delegating.InnerHandler;
        }
        return handler is AdmissionHandler admission && ReferenceEquals(admission.Policy, policy) &&
            admission.Contract == AAuthTransportContract.EnforcesEgressPolicy
            ? new BorrowedHandler(admission, lifetimeOwner) : null;
    }

    public static Task<HttpResponseMessage> SendAsync(HttpClient client, HttpRequestMessage request,
        CancellationToken cancellationToken = default) =>
        SendBoundedAsync(GetPolicy(client), request,
            token => client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token), cancellationToken);

    internal static async Task<HttpResponseMessage> SendBoundedAsync(AAuthEgressPolicy policy,
        HttpRequestMessage request, Func<CancellationToken, Task<HttpResponseMessage>> send,
        CancellationToken cancellationToken)
    {
        policy.ValidateUrl(request.RequestUri?.OriginalString ?? "");
        request.Version = HttpVersion.Version11;
        request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(policy.RequestTimeout);
        var pendingResponse = send(deadline.Token);
        HttpResponseMessage response;
        try { response = await pendingResponse.WaitAsync(deadline.Token).ConfigureAwait(false); }
        catch
        {
            _ = DisposeLateResponseAsync(pendingResponse);
            throw;
        }
        try
        {
            if ((int)response.StatusCode is >= 300 and < 400)
                throw new HttpRequestException("Redirects are not admitted for AAuth fetches.");
            if (response.RequestMessage?.RequestUri is { } finalUri && finalUri.OriginalString != request.RequestUri!.OriginalString)
                throw new HttpRequestException("Injected transport violated its no-redirect contract.");
            var content = response.Content;
            if (content.Headers.ContentLength > policy.MaxResponseBytes)
                throw new HttpRequestException("AAuth response exceeds the configured byte limit.");
            await using var stream = await content.ReadAsStreamAsync(deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[Math.Min(8192, policy.MaxResponseBytes + 1)];
            while (true)
            {
                var count = await stream.ReadAsync(chunk.AsMemory(0,
                    (int)Math.Min(chunk.Length, policy.MaxResponseBytes + 1L - buffer.Length)), deadline.Token)
                    .AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
                if (count == 0) break;
                buffer.Write(chunk, 0, count);
                if (buffer.Length > policy.MaxResponseBytes)
                    throw new HttpRequestException("AAuth response exceeds the configured byte limit.");
            }
            var bounded = new ByteArrayContent(buffer.ToArray());
            foreach (var header in content.Headers) bounded.Headers.TryAddWithoutValidation(header.Key, header.Value);
            response.Content = bounded;
            content.Dispose();
            return response;
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    private sealed class BorrowedHandler(HttpMessageHandler handler, HttpMessageHandler lifetimeOwner) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker _inner = new(handler, disposeHandler: false);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try { return await _inner.SendAsync(request, cancellationToken).ConfigureAwait(false); }
            finally { GC.KeepAlive(lifetimeOwner); }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            GC.KeepAlive(lifetimeOwner);
            base.Dispose(disposing);
        }
    }

    private sealed class AdmissionHandler(AAuthEgressPolicy policy, AAuthTransportContract contract,
        HttpMessageHandler innerHandler) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker _inner = new(innerHandler);
        internal AAuthEgressPolicy Policy => policy;
        internal AAuthTransportContract Contract => contract;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            SendBoundedAsync(policy, request, token => _inner.SendAsync(request, token), cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }

    private static async Task DisposeLateResponseAsync(Task<HttpResponseMessage> response)
    {
        try { (await response.ConfigureAwait(false)).Dispose(); }
        catch { }
    }
}
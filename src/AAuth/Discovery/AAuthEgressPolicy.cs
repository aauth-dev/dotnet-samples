using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Discovery;

/// <summary>Resolves a complete address set. The transport admits every result and connects to a numeric address.</summary>
public interface IAAuthDnsResolver
{
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

/// <summary>Immutable admission policy. Production defaults never admit private destinations.</summary>
public sealed class AAuthEgressPolicy
{
    public static AAuthEgressPolicy Production { get; } = new();
    private static readonly IPNetwork IetfV6Assignments = IPNetwork.Parse("2001::/23");
    private static readonly IPNetwork[] PublicIetfV6Assignments =
    [
        IPNetwork.Parse("2001:1::1/128"), IPNetwork.Parse("2001:1::2/128"),
        IPNetwork.Parse("2001:1::3/128"), IPNetwork.Parse("2001:3::/32"),
        IPNetwork.Parse("2001:4:112::/48"), IPNetwork.Parse("2001:20::/28"),
        IPNetwork.Parse("2001:30::/28"),
    ];
    private static readonly IPNetwork DocumentationV6 = IPNetwork.Parse("2001:db8::/32");
    private static readonly IPNetwork DocumentationV6Extended = IPNetwork.Parse("3fff::/20");
    private readonly HashSet<string> _loopbackOrigins;
    private readonly HashSet<(string Source, string Target)> _jwksOrigins;
    private readonly IAAuthDnsResolver _dns;
    public int MaxResponseBytes { get; }
    public TimeSpan RequestTimeout { get; }

    public AAuthEgressPolicy(IEnumerable<string>? developmentLoopbackOrigins = null,
        IEnumerable<(string Source, string Target)>? crossOriginJwks = null,
        int maxResponseBytes = 1024 * 1024, TimeSpan? requestTimeout = null,
        IAAuthDnsResolver? dnsResolver = null)
    {
        if (maxResponseBytes < 1 || maxResponseBytes > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes));
        RequestTimeout = requestTimeout ?? TimeSpan.FromSeconds(10);
        if (RequestTimeout <= TimeSpan.Zero || RequestTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        MaxResponseBytes = maxResponseBytes;
        _dns = dnsResolver ?? new SystemDnsResolver();
        _loopbackOrigins = new(StringComparer.Ordinal);
        foreach (var origin in developmentLoopbackOrigins ?? [])
        {
            var uri = ParseUrl(origin);
            if (origin != Origin(uri) || (uri.IdnHost != "localhost"
                && uri.IdnHost != "127.0.0.1" && uri.IdnHost != "::1"))
                throw new ArgumentException("Development origins must be exact localhost, 127.0.0.1, or [::1] origins.");
            _loopbackOrigins.Add(origin);
        }
        _jwksOrigins = new();
        foreach (var pair in crossOriginJwks ?? [])
        {
            if (pair.Source != Origin(ValidateUrl(pair.Source)) || pair.Target != Origin(ValidateUrl(pair.Target)))
                throw new ArgumentException("Cross-origin JWKS admission requires exact source and target origins.");
            _jwksOrigins.Add(pair);
        }
    }

    public static AAuthEgressPolicy ForDevelopmentLoopback(params string[] origins) => new(origins);

    internal bool IsDevelopmentIdentifier(string identifier) => _loopbackOrigins.Contains(identifier);
    internal bool IsDevelopmentAgentDomain(string domain) => _loopbackOrigins.Any(origin =>
        new Uri(origin).Host == domain);

    public bool IsValidIdentifier(string? identifier)
    {
        if (identifier is null) return false;
        if (_loopbackOrigins.Contains(identifier)) return true;
        if (!identifier.StartsWith("https://", StringComparison.Ordinal)) return false;
        var host = identifier[8..];
        if (host.Length == 0 || host.Length > 253 || host != host.ToLowerInvariant()
            || host.EndsWith('.') || IPAddress.TryParse(host, out _) || host == "localhost") return false;
        foreach (var label in host.Split('.'))
        {
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-') return false;
            foreach (var character in label)
                if (character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9') and not '-') return false;
        }
        return true;
    }

    public void ValidateIdentifier(string identifier)
    {
        if (!IsValidIdentifier(identifier)) throw new ArgumentException("Invalid exact AAuth server identifier.", nameof(identifier));
    }

    public Uri ValidateUrl(string value, bool endpoint = false)
    {
        var uri = ParseUrl(value);
        var development = _loopbackOrigins.Contains(Origin(uri));
        if (uri.Scheme != "https" && !development)
            throw new HttpRequestException("AAuth egress requires HTTPS or an explicitly configured loopback origin.");
        if (endpoint && value.Contains('?')) throw new HttpRequestException("AAuth endpoint URLs must not contain a query.");
        if (IPAddress.TryParse(uri.IdnHost, out var address)) ValidateAddress(address, development);
        else if ((uri.IdnHost == "localhost" || uri.IdnHost.EndsWith(".localhost", StringComparison.Ordinal)) && !development)
            throw new HttpRequestException("Loopback destination is not admitted.");
        return uri;
    }

    public Uri ValidateJwksUrl(string value, string metadataIdentifier)
    {
        ValidateIdentifier(metadataIdentifier);
        var uri = ValidateUrl(value);
        if (Origin(uri) != metadataIdentifier && !_jwksOrigins.Contains((metadataIdentifier, Origin(uri))))
            throw new HttpRequestException("Cross-origin JWKS requires explicit source/target admission.");
        return uri;
    }

    public async Task ValidateDestinationAsync(string value, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(RequestTimeout);
        await ResolveAsync(ValidateUrl(value), deadline.Token).ConfigureAwait(false);
    }

    public Uri ValidatePendingLocation(Uri endpoint, Uri location)
    {
        if (location.OriginalString.Contains('\\') || location.OriginalString.Contains('#')
            || location.OriginalString.Any(character => character <= 32 || character >= 127))
            throw new HttpRequestException("Invalid pending Location.");
        var pending = location.IsAbsoluteUri ? location : new Uri(endpoint, location);
        ValidateUrl(pending.OriginalString);
        if (Origin(pending) != Origin(endpoint)) throw new HttpRequestException("Pending Location must share the issuing endpoint's origin.");
        return pending;
    }

    internal async Task<IPAddress[]> ResolveAsync(Uri uri, CancellationToken cancellationToken)
    {
        var addresses = IPAddress.TryParse(uri.IdnHost, out var literal) ? [literal]
            : await _dns.ResolveAsync(uri.IdnHost, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0) throw new HttpRequestException("DNS returned no destination addresses.");
        var development = _loopbackOrigins.Contains(Origin(uri));
        foreach (var address in addresses) ValidateAddress(address, development);
        return addresses;
    }

    internal static string Origin(Uri uri) => uri.GetLeftPart(UriPartial.Authority);

    private static Uri ParseUrl(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Any(character => character <= 32 || character >= 127)
            || value.Contains('\\') || value.Contains('#')
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || (uri.Scheme != "https" && uri.Scheme != "http") || uri.UserInfo.Length != 0
            || !value.StartsWith(uri.Scheme + "://", StringComparison.Ordinal))
            throw new HttpRequestException("Invalid outbound URL.");
        var authorityEnd = value.IndexOfAny(['/', '?'], value.IndexOf("://", StringComparison.Ordinal) + 3);
        var authority = authorityEnd < 0 ? value : value[..authorityEnd];
        if (authority != Origin(uri)) throw new HttpRequestException("Outbound URL authority must be canonical ASCII without an explicit default port.");
        return uri;
    }

    internal static void ValidateAddress(IPAddress address, bool development)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (development)
        {
            if (!IPAddress.IsLoopback(address)) throw new HttpRequestException("Configured development origin resolved outside loopback.");
            return;
        }
        var bytes = address.GetAddressBytes();
        var permitted = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => bytes[0] is not (0 or 10 or 127) && bytes[0] < 224
                && !(bytes[0] == 100 && bytes[1] is >= 64 and <= 127)
                && !(bytes[0] == 169 && bytes[1] == 254)
                && !(bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                && !(bytes[0] == 192 && (bytes[1] == 168 || (bytes[1] == 88 && bytes[2] == 99)
                    || (bytes[1] == 0 && (bytes[2] == 2 || (bytes[2] == 0 && bytes[3] is not (9 or 10))))))
                && !(bytes[0] == 198 && (bytes[1] is 18 or 19 || (bytes[1] == 51 && bytes[2] == 100)))
                && !(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113),
            AddressFamily.InterNetworkV6 => address.ScopeId == 0 && (bytes[0] & 0xe0) == 0x20
                && (!IetfV6Assignments.Contains(address) || PublicIetfV6Assignments.Any(network => network.Contains(address)))
                && !(bytes[0] == 0x20 && bytes[1] == 0x02)
                && !DocumentationV6.Contains(address) && !DocumentationV6Extended.Contains(address),
            _ => false,
        };
        if (!permitted) throw new HttpRequestException("Non-public destination address is not admitted.");
    }

    private sealed class SystemDnsResolver : IAAuthDnsResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Dns.GetHostAddressesAsync(host, cancellationToken);
    }
}
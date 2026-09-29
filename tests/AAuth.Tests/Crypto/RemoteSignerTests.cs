using System.Net;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.Time.Testing;

namespace AAuth.Tests.Crypto;

// A KMS/HSM-style signer: signs asynchronously and never exposes its private key.
internal sealed class RemoteSigner(AAuthKey remote) : IAAuthSigner
{
    private int _calls;

    public int Calls => Volatile.Read(ref _calls);
    public string Algorithm => AAuthKey.Ed25519Algorithm;
    public bool HasPrivateKey => true;

    public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _calls);
        return remote.Sign(data.ToArray());
    }

    public bool Verify(byte[] data, byte[] signature) => remote.Verify(data, signature);
    public JsonObject ToPublicJwk() => remote.ToPublicJwk();
    public string ComputeJwkThumbprint() => remote.ComputeJwkThumbprint();
}

public class RemoteSignerTests
{
    private const string Ps = "https://ps.example";
    private const string Resource = "https://resource.example";

    private static readonly IAAuthKey AgentKey = AAuthKey.Generate();

    [Fact(DisplayName = "a remote signer is not exportable")]
    public void RemoteSigner_IsNotExportable()
    {
        IAAuthSigner signer = new RemoteSigner(AAuthKey.Generate());
        Assert.IsNotAssignableFrom<IAAuthExportableKey>(signer);
    }

    [Fact(DisplayName = "a remote signer mints a verifiable agent token")]
    public async Task AgentToken()
    {
        var signer = new RemoteSigner(AAuthKey.Generate());
        var jwt = await new AgentTokenBuilder
        {
            Issuer = "https://ap.example", Subject = "aauth:agent@ap.example",
            Key = signer, KeyId = "ap-1", ConfirmationKey = AgentKey,
        }.BuildAsync();

        var token = new TokenVerifier().Verify(jwt, PublicOf(signer), AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk);
        Assert.Equal("ap-1", (string?)token.Header["kid"]);
        Assert.Equal(1, signer.Calls);
    }

    [Fact(DisplayName = "a remote signer mints a verifiable person token")]
    public async Task PersonToken()
    {
        var signer = new RemoteSigner(AAuthKey.Generate());
        var jwt = await new PersonTokenBuilder
        {
            Issuer = Ps, Audience = Resource, Subject = "person-1", ConfirmationKey = AgentKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30), Key = signer, KeyId = "ps-1",
        }.BuildAsync();

        new TokenVerifier().Verify(jwt, PublicOf(signer), PersonTokenBuilder.TokenType, PersonTokenBuilder.PersonDwk, Resource);
        Assert.Equal(1, signer.Calls);
    }

    [Fact(DisplayName = "a remote signer mints a verifiable auth token")]
    public async Task AuthToken()
    {
        var signer = new RemoteSigner(AAuthKey.Generate());
        var jwt = await new AuthTokenBuilder
        {
            Issuer = Ps, Audience = Resource, PersonServer = Ps, Subject = "person-1",
            AgentConfirmationKey = AgentKey, AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30),
            Key = signer, KeyId = "ps-1", Scope = "read",
        }.BuildAsync();

        new TokenVerifier().Verify(jwt, PublicOf(signer), AuthTokenBuilder.TokenType, AuthTokenBuilder.PersonDwk, Resource);
        Assert.Equal(1, signer.Calls);
    }

    [Fact(DisplayName = "a remote signer mints a verifiable resource token")]
    public async Task ResourceToken()
    {
        var signer = new RemoteSigner(AAuthKey.Generate());
        var jwt = await new ResourceTokenBuilder
        {
            Issuer = Resource, Audience = Ps, PersonServer = Ps, Subject = "person-1",
            PresentedJti = "person-token-1", AgentJkt = AgentKey.ComputeJwkThumbprint(),
            Key = signer, KeyId = "r-1",
        }.BuildAsync();

        new TokenVerifier().Verify(jwt, PublicOf(signer), ResourceTokenBuilder.TokenType, ResourceTokenBuilder.ResourceDwk, Ps);
        Assert.Equal(1, signer.Calls);
    }

    [Fact(DisplayName = "a remote signer signs HTTP requests the verifier accepts")]
    public async Task SignsHttpRequests()
    {
        var signer = new RemoteSigner(AAuthKey.Generate());
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var capture = new CaptureHandler();
        var signing = new AAuthSigningHandler(signer, () => "abc.def.ghi", new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);
        await client.PostAsync($"{Resource}/api", new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));

        var request = capture.Captured!;
        new AAuthVerifier { TimeProvider = new FakeTimeProvider(clock) }.Verify(
            method: "POST",
            authority: "resource.example",
            path: "/api",
            signatureKey: string.Join(',', request.Headers.GetValues("Signature-Key")),
            signatureInput: string.Join(',', request.Headers.GetValues("Signature-Input")),
            signatureHeader: string.Join(',', request.Headers.GetValues("Signature")),
            publicKey: PublicOf(signer),
            fields: new Dictionary<string, string>
            {
                ["content-type"] = request.Content!.Headers.ContentType!.ToString(),
                ["content-digest"] = string.Join(',', request.Content.Headers.GetValues("Content-Digest")),
            });
        Assert.Equal(1, signer.Calls);
    }

    [Fact(DisplayName = "cancellation reaches the remote signer")]
    public async Task Cancellation_ReachesSigner()
    {
        var signer = new RemoteSigner(AAuthKey.Generate());
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new AgentTokenBuilder
        {
            Issuer = "https://ap.example", Subject = "aauth:agent@ap.example", Key = signer, KeyId = "ap-1",
        }.BuildAsync(cancelled.Token).AsTask());
    }

    private static IAAuthKey PublicOf(IAAuthKey key) => KeyFactory.FromPublicJwk(key.ToPublicJwk());

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Captured { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}

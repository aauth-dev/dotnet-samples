using System.Net;
using AAuth.Crypto;
using AAuth.Events.Resource;
using Xunit;

namespace AAuth.Events.Tests.Resource;

public sealed class EventDeliveryTests
{
    private static readonly DateTimeOffset Issued =
        DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);

    [Fact]
    public void FromRegistrationCopiesFactsAndInitializesUses()
    {
        var registration = Registration(maxUses: 2);
        var subscription = ResourceSubscription.FromRegistration(
            registration, registration.ExpiresAt.AddMinutes(-1));

        Assert.Equal(registration.Eid, subscription.Eid);
        Assert.Equal(registration.ApIssuer, subscription.ApIssuer);
        Assert.Equal(registration.AgentSubject, subscription.AgentSubject);
        Assert.Equal(registration.ResourceAudience, subscription.ResourceAudience);
        Assert.Equal(2, subscription.MaxUses);
        Assert.Equal(2, subscription.RemainingUses);
    }

    [Fact]
    public void FromRegistrationDoesNotExtendVerifiedLifetime()
    {
        var registration = Registration();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ResourceSubscription.FromRegistration(registration, registration.ExpiresAt.AddTicks(1)));
    }

    [Fact]
    public void PreparedPayloadAndReturnedCopiesAreDefensive()
    {
        var key = AAuthKey.Generate();
        var subscription = ResourceSubscription.FromRegistration(
            Registration(), Issued.AddMinutes(4));
        var resolver = new AAuth.Events.Discovery.EventEndpointResolver(
            new AAuth.Discovery.MetadataClient(new HttpClient(new NoopHandler())));
        var client = new EventDeliveryClient(
            new HttpClient(new NoopHandler()), resolver, key, "resource-1", () => Issued);
        var payload = new byte[] { 1, 2, 3 };
        var prepared = client.Prepare(subscription, TimeSpan.FromMinutes(1), payload);
        payload[0] = 9;
        var returned = prepared.GetPayloadBytes();
        returned[1] = 8;

        Assert.Equal(new byte[] { 1, 2, 3 }, prepared.GetPayloadBytes());
        Assert.Equal(AAuthEventsConstants.JsonMediaType, prepared.ContentType);
    }

    [Fact]
    public void BodylessPreparedDeliveryHasNoContentType()
    {
        var key = AAuthKey.Generate();
        var subscription = ResourceSubscription.FromRegistration(
            Registration(), Issued.AddMinutes(4));
        var resolver = new AAuth.Events.Discovery.EventEndpointResolver(
            new AAuth.Discovery.MetadataClient(new HttpClient(new NoopHandler())));
        var client = new EventDeliveryClient(
            new HttpClient(new NoopHandler()), resolver, key, "resource-1", () => Issued);
        var prepared = client.Prepare(subscription, TimeSpan.FromMinutes(1));

        Assert.Null(prepared.ContentType);
        Assert.Empty(prepared.GetPayloadBytes());
    }

    [Fact]
    public void PreparationsAtSameTimeHaveDistinctTokens()
    {
        var key = AAuthKey.Generate();
        var subscription = ResourceSubscription.FromRegistration(
            Registration(), Issued.AddMinutes(4));
        var resolver = new AAuth.Events.Discovery.EventEndpointResolver(
            new AAuth.Discovery.MetadataClient(new HttpClient(new NoopHandler())));
        var client = new EventDeliveryClient(
            new HttpClient(new NoopHandler()), resolver, key, "resource-1", () => Issued);

        var first = client.Prepare(subscription, TimeSpan.FromMinutes(1));
        var second = client.Prepare(subscription, TimeSpan.FromMinutes(1));

        Assert.NotEqual(first.TokenId, second.TokenId);
        Assert.NotEqual(first.CompactToken, second.CompactToken);
    }

    private static VerifiedSubscriptionRegistration Registration(long? maxUses = null)
    {
        var key = AAuthKey.Generate();
        return new VerifiedSubscriptionRegistration(
            "https://ap.example",
            "aauth:agent@ap.example",
            "https://resource.example",
            "event-1",
            maxUses,
            key,
            key,
            Issued,
            Issued.AddMinutes(5),
            "ap-1",
            "token");
    }

    private sealed class NoopHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}

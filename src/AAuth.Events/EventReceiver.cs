using AAuth.Tokens;

namespace AAuth.Events;

public sealed class EventReceiver(EventsProtocol protocol, IAgentEventStore store, string agent)
{
    public async Task<bool> ReceiveAsync(string token, byte[] body, CancellationToken cancellationToken = default)
    {
        var verified = await protocol.VerifyEventAsync(token, agent, cancellationToken).ConfigureAwait(false);
        var eid = EventsTokens.RequireText(verified.Payload, "eid");
        var context = store.FindContext(eid);
        if (context is null || context.Resource != verified.Issuer || context.Agent != agent)
            throw new TokenVerificationException("Unknown or mismatched event context.");
        return store.RecordOnce(new(context, new(token, eid, verified.Jti, verified.Issuer, agent, verified.ExpiresAt, body)),
            protocol.TokenVerifier.TimeProvider.GetUtcNow());
    }
}
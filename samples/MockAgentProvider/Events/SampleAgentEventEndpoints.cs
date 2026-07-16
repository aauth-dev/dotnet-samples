using System.Collections.Concurrent;
using System.Text.Json;
using AAuth.Crypto;
using AAuth.Events.AgentProvider;
using AAuth.HttpSig;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace MockAgentProvider.Events;

/// <summary>
/// Non-normative sample AP-to-agent acquisition, polling, and ACK routes.
/// AAuth.Events deliberately does not standardize this transport.
/// </summary>
internal static class SampleAgentEventEndpoints
{
    public static void MapSampleAgentEventEndpoints(
        this WebApplication app,
        ConcurrentDictionary<string, AgentRecord> agents,
        AAuthKey apKey,
        string apKeyId,
        string issuer,
        string bookingsResource,
        TimeSpan tokenLifetime,
        TimeSpan subscriptionLifetime,
        long? subscriptionMaxUses,
        SampleAgentProviderEventStore store)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(agents);
        ArgumentNullException.ThrowIfNull(apKey);
        ArgumentNullException.ThrowIfNull(store);

        app.MapPost("/agents/{agentId}/event-subscriptions/bookings", async (
            HttpContext context,
            string agentId) =>
        {
            if (context.Request.Query.Count != 0 ||
                !IsBodyless(context.Request))
            {
                await WriteErrorAsync(context.Response, StatusCodes.Status400BadRequest,
                    "The sample acquisition request must be bodyless and queryless.");
                return;
            }

            var agent = await AuthenticateAgentAsync(context, agentId, agents);
            if (agent is null)
                return;

            var issuedAt = DateTimeOffset.UtcNow;
            var issuerService = new SubscribeTokenIssuer(
                store,
                new SubscribeTokenIssuerOptions
                {
                    Issuer = issuer,
                    Agent = agent.AgentId,
                    Resource = bookingsResource,
                    KeyId = apKeyId,
                    Key = apKey,
                    ConfirmationKey = agent.PublicKey,
                    TokenLifetime = tokenLifetime,
                    SubscriptionLifetime = subscriptionLifetime,
                    MaxUses = subscriptionMaxUses,
                    Clock = () => issuedAt,
                });
            var artifact = await issuerService.IssueAsync(context.RequestAborted);
            await context.Response.WriteAsJsonAsync(new
            {
                subscribe_token = artifact.CompactToken,
                eid = artifact.Eid,
                expires_at = issuedAt + tokenLifetime,
            }, cancellationToken: context.RequestAborted);
        });

        app.MapGet("/agents/{agentId}/events", async (
            HttpContext context,
            string agentId) =>
        {
            var values = context.Request.Query["limit"];
            if (values.Count > 1 ||
                (values.Count == 1 && (!int.TryParse(values[0], out var parsedLimit) ||
                                        parsedLimit <= 0 || parsedLimit > 100)))
            {
                await WriteErrorAsync(context.Response, StatusCodes.Status400BadRequest,
                    "limit must be an integer from 1 through 100.");
                return;
            }

            var limit = values.Count == 0 ? 20 : int.Parse(values[0]!);
            var agent = await AuthenticateAgentAsync(context, agentId, agents);
            if (agent is null)
                return;

            var pending = await store.ListPendingAsync(agent.AgentId, limit, context.RequestAborted);
            // Sample-only polling is non-destructive. The agent must explicitly
            // ACK each receipt after it has verified and handled the envelope.
            var response = pending.Select(receipt => new
            {
                receipt_id = receipt.ReceiptId,
                event_token = receipt.EventToken,
                payload_base64url = receipt.PayloadBytes.Length == 0
                    ? null
                    : Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(receipt.PayloadBytes),
                content_type = receipt.ContentType,
                received_at = receipt.ReceivedAt,
            });
            await context.Response.WriteAsJsonAsync(response, cancellationToken: context.RequestAborted);
        });

        app.MapPost("/agents/{agentId}/events/{receiptId}/ack", async (
            HttpContext context,
            string agentId,
            string receiptId) =>
        {
            if (!IsBodyless(context.Request))
            {
                await WriteErrorAsync(context.Response, StatusCodes.Status400BadRequest,
                    "The sample ACK request must be bodyless.");
                return;
            }

            var agent = await AuthenticateAgentAsync(context, agentId, agents);
            if (agent is null)
                return;

            var acknowledged = await store.AcknowledgeAsync(
                agent.AgentId, receiptId, context.RequestAborted);
            context.Response.StatusCode = acknowledged
                ? StatusCodes.Status204NoContent
                : StatusCodes.Status404NotFound;
        });
    }

    private static bool IsBodyless(HttpRequest request) =>
        request.ContentLength is null or 0 &&
        !request.Headers.ContainsKey("Transfer-Encoding");

    private static async Task<AgentRecord?> AuthenticateAgentAsync(
        HttpContext context,
        string agentId,
        ConcurrentDictionary<string, AgentRecord> agents)
    {
        if (!agents.TryGetValue(agentId, out var agent))
        {
            await WriteErrorAsync(context.Response, StatusCodes.Status404NotFound,
                "The agent is not enrolled.");
            return null;
        }

        var signatureKeyHeader = SingleHeader(context.Request.Headers, "Signature-Key");
        var signatureInput = SingleHeader(context.Request.Headers, "Signature-Input");
        var signature = SingleHeader(context.Request.Headers, "Signature");
        if (signatureKeyHeader is null || signatureInput is null || signature is null)
        {
            await WriteErrorAsync(context.Response, StatusCodes.Status401Unauthorized,
                "The sample route requires an enrolled agent HTTP signature.");
            return null;
        }

        try
        {
            var parsed = SignatureKeyParser.ParseAny(signatureKeyHeader);
            if (!string.Equals(parsed.Scheme, "hwk", StringComparison.Ordinal) ||
                parsed.ConfirmationKey is null ||
                !string.Equals(parsed.Jkt, parsed.ConfirmationKey.ComputeJwkThumbprint(),
                    StringComparison.Ordinal) ||
                !string.Equals(parsed.ConfirmationKey.ComputeJwkThumbprint(),
                    agent.PublicKey.ComputeJwkThumbprint(), StringComparison.Ordinal))
            {
                throw new AAuthVerificationException("The signature key is not the enrolled agent key.");
            }

            new AAuthVerifier
            {
                MaxAge = TimeSpan.FromSeconds(120),
            }.Verify(
                context.Request.Method,
                context.Request.Host.ToString(),
                context.Request.Path,
                signatureKeyHeader,
                signatureInput,
                signature,
                agent.PublicKey);
            return agent;
        }
        catch (Exception ex) when (ex is AAuthVerificationException or
                                   FormatException or ArgumentException)
        {
            await WriteErrorAsync(context.Response, StatusCodes.Status401Unauthorized,
                "The enrolled agent HTTP signature is invalid.");
            return null;
        }
    }

    private static string? SingleHeader(IHeaderDictionary headers, string name)
    {
        StringValues values = headers[name];
        return values.Count == 1 ? values[0] : null;
    }

    private static Task WriteErrorAsync(HttpResponse response, int status, string description)
    {
        response.StatusCode = status;
        return response.WriteAsJsonAsync(
            new { error = "invalid_request", error_description = description });
    }
}

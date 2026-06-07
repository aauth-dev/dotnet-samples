# Clarification Chat

> [Clarification Chat](https://explorer.aauth.dev/missions/clarification)

## Overview

A clarification chat is the protocol's way for a server to ask the agent a
follow-up question before it decides a deferred request, rather than approving or
rejecting outright (§Clarification Chat). Two places use it:

- **Token exchange.** When the agent exchanges a resource token, the PS may need
  more detail before granting the scope — it defers and asks a clarifying
  question.
- **Mission proposal and governance.** When the agent proposes a mission or
  requests permission, the PS may ask the agent to refine the intent before
  approving.

The agent answers the question, replaces its request with a narrower one, or
withdraws — and the exchange continues until the server decides or the round
limit is reached.

## The question: `ClarificationRequirement`

When a server needs clarification it returns `AAuth-Requirement:
requirement=clarification` and carries the question in the response body. The SDK
projects that into a typed `ClarificationRequirement`:

```csharp
namespace AAuth.Headers;

public sealed record ClarificationRequirement(
    string Clarification,                   // the Markdown question — UNTRUSTED, sanitize before display
    int? TimeoutSeconds = null,             // optional deadline to respond by
    IReadOnlyList<string>? Options = null); // optional discrete choices for a closed question
```

> [!WARNING]
> The `Clarification` value is untrusted input from the server. Sanitize it
> before rendering it to a user (§Clarification Required).

## The answer: `ClarificationResponse`

The agent replies with one of three actions (§Agent Response to Clarification):

```csharp
namespace AAuth.Agent;

public sealed class ClarificationResponse
{
    public enum Kind { Respond, Update, Cancel }

    public static ClarificationResponse Respond(string markdown);                       // answer the question
    public static ClarificationResponse Update(string resourceToken, string? justification = null); // replace the request
    public static ClarificationResponse Cancel();                                       // withdraw
}
```

- `Respond` posts a Markdown answer and resumes the exchange.
- `Update` replaces the original request with a new resource token (for example a
  reduced scope) plus an optional justification.
- `Cancel` withdraws the request entirely.

## Driving the chat: `ClarificationExchange`

For manual control over a deferred pending URL, use `ClarificationExchange`. It
tracks the round count and enforces a maximum (§Clarification Limits).

```csharp
namespace AAuth.Agent;

public sealed class ClarificationExchange
{
    public const int DefaultMaxRounds = 5;

    public ClarificationExchange(HttpClient signedClient, Uri pendingUrl, int maxRounds = DefaultMaxRounds);

    public int MaxRounds { get; }
    public int Rounds { get; }

    public Task ApplyAsync(ClarificationResponse response, CancellationToken ct = default);
    public Task RespondAsync(string markdown, CancellationToken ct = default);
    public Task UpdateRequestAsync(string resourceToken, string? justification = null, CancellationToken ct = default);
    public Task CancelAsync(CancellationToken ct = default);
}
```

The supplied `HttpClient` must be wired with the agent's `AAuthSigningHandler` so
every POST/DELETE to the pending URL is signed.

```csharp
var exchange = new ClarificationExchange(signedClient, pendingUrl);

await exchange.ApplyAsync(ClarificationResponse.Respond(
    "The export is for the user's own tax records, read-only."));

// Cancelling throws AAuthClarificationCancelledException after withdrawing.
// Exceeding MaxRounds throws AAuthClarificationLimitException(MaxRounds).
```

Both `Respond` and `Update` consume a round; `Cancel` issues a DELETE and throws
`AAuthClarificationCancelledException`. Once `Rounds` reaches `MaxRounds` the next
attempt throws `AAuthClarificationLimitException`.

## Automatic handling during token exchange

You rarely need to drive the exchange by hand. The token-exchange request exposes
a callback the SDK invokes whenever the PS asks for clarification, looping until
the PS decides or `MaxClarificationRounds` is hit.

```csharp
var request = new TokenExchangeRequest
{
    MaxClarificationRounds = ClarificationExchange.DefaultMaxRounds,
    OnClarificationRequired = async (requirement, ct) =>
    {
        // requirement.Clarification is untrusted — sanitize before display.
        string question = Sanitize(requirement.Clarification);

        if (requirement.Options is { Count: > 0 } options)
        {
            string choice = await AskUserToPick(question, options);
            return ClarificationResponse.Respond(choice);
        }

        string answer = await AskUser(question);
        return ClarificationResponse.Respond(answer);
    },
};

var authToken = await exchangeClient.ExchangeAsync(personServer, resourceToken, request);
```

## Automatic handling during governance

The same pattern applies to the governance clients. Supply
`OnClarificationRequired` (and optionally `MaxClarificationRounds`) on
`GovernanceOptions` when proposing a mission or requesting permission. The
governance client is **bound** to its Person Server, so no per-call PS URL is
needed:

```csharp
var session = await governance.ProposeMissionAsync(
    new MissionProposal("Reconcile last month's invoices."),
    new GovernanceOptions
    {
        MaxClarificationRounds = 3,
        OnClarificationRequired = async (requirement, ct) =>
            ClarificationResponse.Respond(await AskUser(Sanitize(requirement.Clarification))),
    });
```

When the callback is `null` and the server asks for clarification, the request
fails rather than blocking.

## Further reading

- [Mission Governance Clients](mission-governance-clients.md) — where governance clarification fits
- [Mission Call Chain sample](../../samples/SampleApp/Components/Pages/MissionCallChain.razor) — a clarification round during an out-of-mission elevated-scope exchange, followed by a mission-forwarded call chain
- [Deferred Consent](../workflows/deferred-consent.md) — the broader deferred-response lifecycle
- [Error Handling](error-handling.md) — `AAuthClarificationCancelledException`, `AAuthClarificationLimitException`
- [Missions](missions.md) — the mission model

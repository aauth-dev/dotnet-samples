using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Access;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;

namespace MockAccessServer.Policy;

/// <summary>
/// Delegates the access decision to Keycloak's Authorization Services. The
/// decision is bound to an interactive Keycloak user session: the first
/// evaluation returns <see cref="AccessDecisionKind.NeedsInteraction"/> so the
/// AS sends the user's browser through the OIDC authorization-code login (and
/// Keycloak consent). On the callback the AS exchanges the code for the user's
/// access token and asks Keycloak for an <c>uma-ticket</c>
/// <c>response_mode=decision</c> verdict, pushing the PS-asserted claims via
/// the <c>claim_token</c> for ABAC policies.
///
/// <para><b>Identity-claims gathering (§Claims Required, Option B).</b> When a
/// Keycloak policy needs an attribute the AS did not push, the UMA grant
/// responds <c>403</c> with <c>error=need_info</c>, a <c>required_claims</c>
/// descriptor, and a fresh <c>ticket</c>. The adapter maps that to
/// <see cref="AccessDecision.NeedsClaims"/>, parks the ticket and the user
/// token against the interaction id, and — when the Person Server pushes the
/// claims — re-submits the UMA grant with the pushed values in the
/// <c>claim_token</c> plus the returned <c>ticket</c>. Keycloak becomes the
/// dynamic source of the requirement (a claim-gathering policy is a realm-import
/// addition; absent it, the simpler config-declared path still works).</para>
///
/// AAuth crypto stays in the adapter; Keycloak is only the Policy Decision
/// Point. Failures to reach Keycloak surface as exceptions so the AS fails
/// closed (never a silent allow).
/// </summary>
public sealed class KeycloakAccessPolicy : IAccessPolicy, IInteractiveAccessPolicy
{
    private readonly HttpClient _http;
    private readonly KeycloakOptions _options;

    // Per-interaction state for the claim-gathering re-decide. A production
    // adapter would persist these with a TTL; the demo keys them by the AS
    // pending-interaction id.
    private readonly ConcurrentDictionary<string, string> _userTokens = new();
    private readonly ConcurrentDictionary<string, string> _tickets = new();

    public KeycloakAccessPolicy(HttpClient http, KeycloakOptions options)
    {
        _http = http;
        _options = options;
    }

    /// <summary>
    /// First-pass evaluation requires interaction: the policy decision is bound
    /// to a Keycloak user session that does not exist yet, so the AS turns this
    /// into a <c>202 requirement=interaction</c>. When the request resumes after
    /// a §Claims Required push (<see cref="AccessPolicyRequest.InteractionId"/>
    /// set with a parked ticket), the adapter re-submits the UMA grant with the
    /// pushed claims and the gathered ticket instead.
    /// </summary>
    public async Task<AccessDecision> EvaluateAsync(
        AccessPolicyRequest request, CancellationToken cancellationToken = default)
    {
        if (request.InteractionId is { } interactionId
            && _tickets.TryGetValue(interactionId, out var ticket)
            && _userTokens.TryGetValue(interactionId, out var userToken))
        {
            // Claims-push re-decide: feed the pushed claims + the gathered
            // ticket back into Keycloak for the final verdict.
            return await DecideAsync(userToken, request, ticket, cancellationToken).ConfigureAwait(false);
        }

        return AccessDecision.NeedsInteraction();
    }

    public string BuildAuthorizationUrl(string state, string redirectUri)
    {
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = _options.ClientId,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["redirect_uri"] = redirectUri,
            ["state"] = state,
            // Force Keycloak to render its consent screen on every login so the
            // user explicitly approves the AS — matching the stub AS UX. Without
            // this (and with the realm client's "Consent Required" off) Keycloak
            // would authenticate silently and redirect straight back.
            ["prompt"] = "consent",
        };
        var qs = string.Join('&', query.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value ?? string.Empty)}"));
        return $"{_options.AuthorizationEndpoint}?{qs}";
    }

    public async Task<AccessDecision> CompleteAsync(
        string code, string redirectUri, AccessPolicyRequest request, CancellationToken cancellationToken = default)
    {
        // 1. Exchange the authorization code for the user's access token.
        var userAccessToken = await ExchangeCodeAsync(code, redirectUri, cancellationToken)
            .ConfigureAwait(false);

        if (request.InteractionId is { } interactionId)
        {
            _userTokens[interactionId] = userAccessToken;
        }

        // 2. Ask Keycloak for a policy decision (uma-ticket, response_mode=decision),
        //    pushing the PS-asserted claims so ABAC policies can evaluate them.
        return await DecideAsync(userAccessToken, request, ticket: null, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<string> ExchangeCodeAsync(
        string code, string redirectUri, CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = _options.ClientId,
            ["client_secret"] = _options.ClientSecret,
        });

        using var response = await _http.PostAsync(_options.TokenEndpoint, form, cancellationToken)
            .ConfigureAwait(false);
        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Keycloak code exchange failed ({(int)response.StatusCode}): {json}");
        }

        var token = (string?)(JsonNode.Parse(json) as JsonObject)?["access_token"];
        if (string.IsNullOrEmpty(token))
        {
            throw new HttpRequestException("Keycloak code exchange returned no access_token.");
        }

        return token;
    }

    private async Task<AccessDecision> DecideAsync(
        string userAccessToken, AccessPolicyRequest request, string? ticket, CancellationToken cancellationToken)
    {
        var fields = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:uma-ticket",
            ["audience"] = _options.ResourceServerAudience ?? _options.ClientId,
            ["response_mode"] = "decision",
        };

        // On the claim-gathering re-decide, resubmit the gathered ticket;
        // otherwise request the permission for the resource + scope.
        if (ticket is not null)
        {
            fields["ticket"] = ticket;
        }
        else
        {
            fields["permission"] = $"{_options.ResourceName}#{request.Scope}";
        }

        // Push the PS-asserted claims so Keycloak ABAC/JS/claim-gathering
        // policies can read them (e.g. the whoami-admin role gate, or a tenant
        // attribute).
        if (request.Claims is not null)
        {
            var claimTokenJson = request.Claims.ToJsonString();
            fields["claim_token"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(claimTokenJson));
            fields["claim_token_format"] = "urn:ietf:params:oauth:token-type:jwt";
        }

        using var umaForm = new FormUrlEncodedContent(fields);
        using var umaRequest = new HttpRequestMessage(HttpMethod.Post, _options.TokenEndpoint)
        {
            Content = umaForm,
        };
        umaRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userAccessToken);

        using var response = await _http.SendAsync(umaRequest, cancellationToken).ConfigureAwait(false);
        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.Forbidden
            || response.StatusCode == HttpStatusCode.Unauthorized)
        {
            // §Claims Required (Option B): Keycloak signals it needs more
            // attributes via error=need_info + a required_claims descriptor and
            // a fresh ticket. Park the ticket and ask the PS to push the claims.
            if (request.InteractionId is { } interactionId
                && TryParseNeedInfo(json, out var requiredClaims, out var gatheredTicket))
            {
                _tickets[interactionId] = gatheredTicket;
                return AccessDecision.NeedsClaims(requiredClaims);
            }

            return AccessDecision.Deny(
                $"Keycloak denied '{_options.ResourceName}#{request.Scope}'");
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Keycloak decision request failed ({(int)response.StatusCode}): {json}");
        }

        var result = (bool?)(JsonNode.Parse(json) as JsonObject)?["result"] ?? false;
        return result
            ? AccessDecision.Allow()
            : AccessDecision.Deny($"Keycloak denied '{_options.ResourceName}#{request.Scope}'");
    }

    // Parse a Keycloak UMA `need_info` error body into the requested claim
    // names and the gathering ticket. Shape (Keycloak Authorization Services):
    //   { "error": "need_info", "ticket": "...",
    //     "required_claims": [ { "name": "tenant", ... }, ... ] }
    private static bool TryParseNeedInfo(
        string json, out IReadOnlyList<string> requiredClaims, out string ticket)
    {
        requiredClaims = [];
        ticket = string.Empty;

        if (JsonNode.Parse(json) is not JsonObject obj
            || (string?)obj["error"] != "need_info")
        {
            return false;
        }

        ticket = (string?)obj["ticket"] ?? string.Empty;

        var names = new List<string>();
        if (obj["required_claims"] is JsonArray claims)
        {
            foreach (var claim in claims)
            {
                if ((string?)claim?["name"] is { Length: > 0 } name)
                {
                    names.Add(name);
                }
            }
        }

        requiredClaims = names;
        return ticket.Length > 0 && names.Count > 0;
    }
}

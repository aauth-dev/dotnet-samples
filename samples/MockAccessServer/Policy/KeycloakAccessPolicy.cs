using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

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
/// AAuth crypto stays in the adapter; Keycloak is only the Policy Decision
/// Point. Failures to reach Keycloak surface as exceptions so the AS fails
/// closed (never a silent allow).
/// </summary>
public sealed class KeycloakAccessPolicy : IAccessPolicy, IInteractiveAccessPolicy
{
    private readonly HttpClient _http;
    private readonly KeycloakOptions _options;

    public KeycloakAccessPolicy(HttpClient http, KeycloakOptions options)
    {
        _http = http;
        _options = options;
    }

    /// <summary>
    /// First-pass evaluation always requires interaction: the policy decision
    /// is bound to a Keycloak user session that does not exist yet. The AS
    /// turns this into a <c>202 requirement=interaction</c>; the real verdict
    /// is produced by <see cref="CompleteAsync"/> after the user logs in.
    /// </summary>
    public Task<AccessDecision> EvaluateAsync(
        AccessPolicyRequest request, CancellationToken cancellationToken = default)
        => Task.FromResult(AccessDecision.NeedsInteraction(interactionUrl: string.Empty));

    public string BuildAuthorizationUrl(string state, string redirectUri)
    {
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = _options.ClientId,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["redirect_uri"] = redirectUri,
            ["state"] = state,
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

        // 2. Ask Keycloak for a policy decision (uma-ticket, response_mode=decision),
        //    pushing the PS-asserted claims so ABAC policies can evaluate them.
        return await DecideAsync(userAccessToken, request, cancellationToken).ConfigureAwait(false);
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
        string userAccessToken, AccessPolicyRequest request, CancellationToken cancellationToken)
    {
        var fields = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:uma-ticket",
            ["audience"] = _options.ResourceServerAudience ?? _options.ClientId,
            ["permission"] = $"{_options.ResourceName}#{request.Scope}",
            ["response_mode"] = "decision",
        };

        // Push the PS-asserted claims so Keycloak ABAC/JS policies can read
        // them (e.g. the whoami-admin role gate on the elevated scope).
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

        if (response.StatusCode == HttpStatusCode.Forbidden
            || response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return AccessDecision.Deny(
                $"Keycloak denied '{_options.ResourceName}#{request.Scope}'");
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
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
}

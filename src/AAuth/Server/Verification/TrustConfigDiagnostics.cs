using System;
using Microsoft.Extensions.Logging;

namespace AAuth.Server.Verification;

/// <summary>
/// Startup footgun guards for AAuth trust configuration. Diagnostics only — these
/// never change runtime policy; they surface two configuration hazards at startup.
/// </summary>
internal static class TrustConfigDiagnostics
{
    /// <summary>
    /// Validate a resource verification pipeline's trust configuration.
    /// <list type="bullet">
    /// <item><description><b>Fail-fast (throw):</b> a trust policy is configured but
    /// <paramref name="requireIssuerVerification"/> is <c>false</c> (signature-only),
    /// so the policy would be silently ignored — an unambiguous misconfiguration.</description></item>
    /// <item><description><b>Warn:</b> issuer verification is on but no auth-token
    /// trust policy is configured, so the resource accepts auth tokens from any
    /// verifiable Person Server (the spec default). Any explicit policy — including
    /// <see cref="AAuthTrust.Any"/> — states intent and suppresses the warning.</description></item>
    /// </list>
    /// </summary>
    public static void Validate(
        ILogger? logger,
        bool requireIssuerVerification,
        bool authTrustConfigured,
        bool agentTrustConfigured,
        string contextLabel)
    {
        if (!requireIssuerVerification && (authTrustConfigured || agentTrustConfigured))
        {
            throw new InvalidOperationException(
                $"AAuth ({contextLabel}): a trust policy (TrustedAuthTokenIssuers / " +
                "IsTrustedAuthTokenIssuer / TrustedAgentProviderIssuers / IsTrustedAgentProviderIssuer) " +
                "is configured, but RequireIssuerVerification is false (signature-only). The trust policy " +
                "would be silently ignored. Move it to an auth-token (RequireAAuth) pipeline, or remove it.");
        }

        if (requireIssuerVerification && !authTrustConfigured)
        {
            logger?.LogWarning(
                "AAuth ({Context}): auth-token endpoints accept any verifiable Person Server because no " +
                "TrustedAuthTokenIssuers / IsTrustedAuthTokenIssuer policy is configured (the AAuth spec " +
                "default for PS-asserted access). Configure a policy to restrict, or assign AAuthTrust.Any " +
                "to declare intentional open trust and silence this warning.",
                contextLabel);
        }
    }

    /// <summary>
    /// Warn when a Person Server / Access Server federation gate has no trust
    /// configured, so it brokers/federates with any verifiable counterparty (the
    /// spec default). Suppressed by any explicit policy (including the sentinel).
    /// </summary>
    public static void WarnIfOpenFederation(
        ILogger? logger, bool trustConfigured, string contextLabel, string message)
    {
        if (!trustConfigured)
        {
            logger?.LogWarning("AAuth ({Context}): {Message}", contextLabel, message);
        }
    }
}

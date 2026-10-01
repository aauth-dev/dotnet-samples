using System;
using System.Collections.Generic;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Server.Verification;

internal static class AAuthResourceVerificationDefaults
{
    internal static AAuthVerificationOptions Normalize(
        AAuthVerificationOptions source,
        string? accessServer,
        IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(services);

        var options = source.Clone();
        if (string.IsNullOrEmpty(accessServer))
        {
            if (!source.IsExpectedAuthTokenDwkConfigured)
            {
                options.UseDefaultExpectedAuthTokenDwk(AAuthConstants.DwkFiles.Person);
            }
            ValidateExpectedDwk(options.ExpectedAuthTokenDwk);
            return options;
        }

        if (!AAuthUrl.IsHttpsOrLoopback(accessServer, options.EgressPolicy))
        {
            throw new InvalidOperationException("AccessServer must be an absolute https URL (loopback http allowed for development).");
        }

        if (!source.IsExpectedAuthTokenDwkConfigured)
        {
            options.UseDefaultExpectedAuthTokenDwk(AAuthConstants.DwkFiles.Access);
        }
        ValidateExpectedDwk(options.ExpectedAuthTokenDwk);

        if (options.ExpectedAuthTokenDwk == AAuthConstants.DwkFiles.Person)
        {
            throw new InvalidOperationException(
                "A four-party resource must verify auth tokens with dwk=aauth-access.json, " +
                "or set ExpectedAuthTokenDwk to null and provide a TokenDwk-aware IAAuthTrustPolicy for mixed mode.");
        }

        var authRule = source.Trust.AuthTokenIssuers;
        if (ReferenceEquals(authRule.Predicate, AAuthTrust.Any))
        {
            throw new InvalidOperationException(
                "AAuthTrust.Any cannot be combined with AccessServer. Four-party resources derive AS-only trust by default; " +
                "mixed mode requires ExpectedAuthTokenDwk = null and an explicit TokenDwk-aware IAAuthTrustPolicy.");
        }

        var hasPolicy = source.Trust.Policy is not null
            || services.GetService<IServiceProviderIsService>()?.IsService(typeof(IAAuthTrustPolicy)) == true;
        if (options.ExpectedAuthTokenDwk is null && !hasPolicy)
        {
            throw new InvalidOperationException(
                "Mixed auth-token DWK verification requires ExpectedAuthTokenDwk = null and an explicit TokenDwk-aware IAAuthTrustPolicy.");
        }

        if (authRule.Allowed is not null && !authRule.Allowed.Contains(accessServer))
        {
            throw new InvalidOperationException(
                $"A four-party resource challenges for AccessServer '{accessServer}' but Trust.AuthTokenIssuers.Allowed does not include it.");
        }

        if (!source.Trust.IsConfigured(AAuthTrustedParty.AuthTokenIssuer, services))
        {
            options.Trust = DeriveFourPartyTrust(source.Trust, accessServer);
        }

        return options;
    }

    private static void ValidateExpectedDwk(string? expectedDwk)
    {
        if (expectedDwk is not null
            && expectedDwk is not (AuthTokenBuilder.PersonDwk or AuthTokenBuilder.AccessDwk))
        {
            throw new InvalidOperationException(
                $"ExpectedAuthTokenDwk must be '{AuthTokenBuilder.PersonDwk}', '{AuthTokenBuilder.AccessDwk}', or null.");
        }
    }

    private static AAuthTrustOptions DeriveFourPartyTrust(AAuthTrustOptions source, string accessServer)
        => new()
        {
            AuthTokenIssuers = new AAuthTrustRule
            {
                Allowed = new HashSet<string>(StringComparer.Ordinal) { accessServer },
            },
            PersonServers = source.PersonServers.IsConfigured
                ? CloneRule(source.PersonServers)
                : new AAuthTrustRule { Predicate = AAuthTrust.Any },
            AgentProviders = CloneRule(source.AgentProviders),
            AccessServers = CloneRule(source.AccessServers),
            Policy = source.Policy,
        };

    private static AAuthTrustRule CloneRule(AAuthTrustRule rule)
        => new()
        {
            Allowed = rule.Allowed,
            Predicate = rule.Predicate,
            PredicateAsync = rule.PredicateAsync,
        };
}

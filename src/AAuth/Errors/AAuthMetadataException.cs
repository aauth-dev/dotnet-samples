using System;

namespace AAuth.Errors;

/// <summary>
/// Thrown when a fetched well-known metadata document fails verification — most
/// importantly when its <c>issuer</c> does not match the URL it was retrieved
/// from. Per the AAuth protocol §Metadata Documents (draft-02), implementations
/// MUST verify that the document's <c>issuer</c> equals the URL minus the
/// <c>/.well-known/{dwk}</c> suffix and MUST reject the document on mismatch.
/// </summary>
/// <remarks>
/// This check prevents host-poisoned metadata: an attacker hosting a document at
/// one origin that claims an <c>issuer</c> of a different origin. Without it, a
/// permissive verifier following the document's <c>jwks_uri</c> could end up
/// trusting attacker-controlled keys for tokens claiming the impersonated issuer.
/// </remarks>
public sealed class AAuthMetadataException : Exception
{
    /// <summary>The URL the metadata document was fetched from.</summary>
    public Uri DocumentUrl { get; }

    /// <summary>The <c>issuer</c> value claimed by the document, if any.</summary>
    public string? ClaimedIssuer { get; }

    /// <summary>The issuer expected from the fetch URL (scheme + host).</summary>
    public string? ExpectedIssuer { get; }

    /// <summary>Create a metadata-verification exception.</summary>
    public AAuthMetadataException(Uri documentUrl, string? claimedIssuer, string? expectedIssuer)
        : base(BuildMessage(documentUrl, claimedIssuer, expectedIssuer))
    {
        DocumentUrl = documentUrl;
        ClaimedIssuer = claimedIssuer;
        ExpectedIssuer = expectedIssuer;
    }

    private static string BuildMessage(Uri documentUrl, string? claimedIssuer, string? expectedIssuer) =>
        $"Metadata at {documentUrl} declares issuer '{claimedIssuer ?? "(none)"}' but was " +
        $"fetched from '{expectedIssuer}'. The document is rejected to prevent host-poisoned " +
        "metadata (§Metadata Documents).";
}

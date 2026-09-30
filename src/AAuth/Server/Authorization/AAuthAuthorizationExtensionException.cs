namespace AAuth.Server.Authorization;

/// <summary>An authorization endpoint extension rejected its request members.</summary>
public sealed class AAuthAuthorizationExtensionException : Exception
{
    public AAuthAuthorizationExtensionException(string error, string? detail = null, Exception? innerException = null)
        : base(detail ?? error, innerException)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(error);
        Error = error;
        Detail = detail;
    }

    public string Error { get; }

    public string? Detail { get; }
}

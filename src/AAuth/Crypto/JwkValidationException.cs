using AAuth.Errors;

namespace AAuth.Crypto;

public sealed class JwkValidationException : ArgumentException
{
    public SignatureErrorCode Code { get; }

    public JwkValidationException(SignatureErrorCode code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;
}
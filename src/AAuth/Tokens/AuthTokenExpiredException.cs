using System;

namespace AAuth.Tokens;

public sealed class AuthTokenExpiredException : InvalidOperationException
{
    public AuthTokenExpiredException() : base("The verified authorization context has expired.") { }
}
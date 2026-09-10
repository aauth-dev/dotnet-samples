using System;

namespace AAuth.Server;

public sealed record TokenGrant(TokenKey Token, string Resource, DateTimeOffset ExpiresAt);
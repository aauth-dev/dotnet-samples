using AAuth.Headers;

namespace ConsentSupport;

/// <summary>Where a person decides an agent's PS consent request.</summary>
public static class PersonServerConsent
{
    /// <summary>The PS consent dashboard, optionally highlighting the request with <paramref name="code"/>.</summary>
    public static string DashboardUrl(string personServer, string? code = null)
    {
        var dashboard = personServer.TrimEnd('/') + "/dashboard";
        return string.IsNullOrEmpty(code) ? dashboard : dashboard + "?code=" + Uri.EscapeDataString(code);
    }

    /// <summary>
    /// Rebuild the <see cref="Interaction"/> behind a resource-initiated interaction
    /// callback, which receives the user URL (with <c>code</c> appended) and the code.
    /// </summary>
    public static Interaction FromUserUrl(string userUrl, string code)
    {
        var suffix = "code=" + Uri.EscapeDataString(code);
        var url = userUrl.EndsWith(suffix, StringComparison.Ordinal) && userUrl.Length > suffix.Length
            ? userUrl[..^(suffix.Length + 1)]
            : userUrl;
        return new Interaction(url, code);
    }

    /// <summary>
    /// Whether the PS hosts <paramref name="interaction"/>, so its dashboard can decide it
    /// (#user-interaction). Access Server logins and resource-owner hops are hosted elsewhere.
    /// </summary>
    public static bool IsPersonServerHosted(string? personServer, Interaction interaction)
    {
        if (string.IsNullOrEmpty(personServer)
            || !Uri.TryCreate(personServer, UriKind.Absolute, out var server)
            || !Uri.TryCreate(interaction.Url, UriKind.Absolute, out var url))
            return false;
        var path = url.AbsolutePath.TrimEnd('/');
        return Uri.Compare(server, url, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0
            && path.Equals(server.AbsolutePath.TrimEnd('/') + "/interaction", StringComparison.Ordinal);
    }
}

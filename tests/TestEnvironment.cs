using System.Runtime.CompilerServices;

namespace AAuth.Testing;

internal static class TestEnvironment
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("DOTNET_ENVIRONMENT", "Development");
    }
}

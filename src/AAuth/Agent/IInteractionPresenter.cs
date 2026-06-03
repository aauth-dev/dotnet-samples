using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// Abstraction for presenting interactions to the user. Agents plug in
/// browser-open, push notification, desktop toast, Blazor UI callback, etc.
/// </summary>
public interface IInteractionPresenter
{
    /// <summary>
    /// Present the interaction URL + code to the user.
    /// Returns when the user has been notified (not when they've completed it).
    /// </summary>
    Task PresentAsync(Interaction interaction, CancellationToken ct = default);
}

/// <summary>
/// Console-based interaction presenter. Writes URL and code to stdout.
/// </summary>
public sealed class ConsoleInteractionPresenter : IInteractionPresenter
{
    /// <inheritdoc/>
    public Task PresentAsync(Interaction interaction, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(interaction);
        Console.WriteLine($"Please visit: {interaction.Url}");
        if (!string.IsNullOrEmpty(interaction.Code))
        {
            Console.WriteLine($"Enter code: {interaction.Code}");
        }
        return Task.CompletedTask;
    }
}

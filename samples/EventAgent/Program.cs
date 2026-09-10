using AAuth.Samples.Events;

var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aauth", "event-agent");
using var session = new EventDemoSession(directory)
{
    Protected = args.Contains("--protected", StringComparer.Ordinal),
    Account = args.Contains("--work", StringComparer.Ordinal) ? "work" : "personal"
};
session.Changed = () =>
{
    Console.WriteLine("Consent: " + session.ConsentUrl);
    return Task.CompletedTask;
};
Console.WriteLine("Events single-shot demo; AP polling and event trigger are local sample APIs.");
while (session.Step < EventDemoSession.Steps.Length)
{
    Console.WriteLine($"{session.Step + 1}. {EventDemoSession.Steps[session.Step]}");
    await session.NextAsync();
    var evidence = session.Evidence[^1];
    Console.WriteLine($"HTTP {evidence.StatusCode}: {evidence.Exchange}");
    Console.WriteLine(evidence.Json);
}
namespace AAuth.Samples.Shared;

public sealed record ProtocolParticipant(string Id, string Label);

public sealed record ProtocolMessage(
    int Step,
    string Kind,
    string From,
    string To,
    string Label,
    bool? Protected = null,
    bool HasResponse = false,
    string ResponseLabel = "response")
{
    public static ProtocolMessage Http(int step, string kind, string from, string to,
        string label, string responseLabel, bool? protectedFlow = null)
        => new(step, kind, from, to, label, protectedFlow, true, responseLabel);

    public static ProtocolMessage Signal(int step, string from, string to, string label)
        => new(step, "network", from, to, label);

    public static ProtocolMessage Local(int step, string actor, string label, bool? protectedFlow = null)
        => new(step, "local", actor, actor, label, protectedFlow);
}

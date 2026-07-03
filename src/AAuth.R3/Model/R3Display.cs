using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>Human-readable R3 display metadata.</summary>
public sealed record R3Display
{
    [JsonPropertyName("summary")]
    [JsonPropertyOrder(1)]
    public string? Summary { get; init; }

    [JsonPropertyName("implications")]
    [JsonPropertyOrder(2)]
    public string? Implications { get; init; }

    [JsonPropertyName("data_accessed")]
    [JsonPropertyOrder(3)]
    public string? DataAccessed { get; init; }

    [JsonPropertyName("irreversible")]
    [JsonPropertyOrder(4)]
    public string? Irreversible { get; init; }

    [JsonPropertyName("detail")]
    [JsonPropertyOrder(5)]
    public string? Detail { get; init; }

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Summary))
        {
            throw new InvalidOperationException("display.summary is required when display is present.");
        }
    }
}

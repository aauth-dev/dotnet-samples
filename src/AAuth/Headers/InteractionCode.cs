using System;
using System.Security.Cryptography;
using System.Text;

namespace AAuth.Headers;

/// <summary>
/// Generates and validates interaction <c>code</c> values per the AAuth protocol
/// §Interaction Code Format. The code is a <b>correlation identifier</b>, not an
/// authorization credential: it ties the user's browser session to the pending
/// interaction so the server can look up the correct request. The person's
/// approve/deny decision MUST be recorded via an authenticated channel at the PS —
/// the code alone MUST NOT authorize the decision (§Interaction Relay). The SDK
/// owns a single correct implementation that servers use to mint codes and
/// correlate user input.
/// </summary>
/// <remarks>
/// Rules implemented here (the pure-function parts of the spec):
/// <list type="bullet">
/// <item><b>Alphabet</b>: Crockford base32 (<c>0123456789ABCDEFGHJKMNPQRSTVWXYZ</c>),
///   which omits the visually ambiguous <c>I</c>, <c>L</c>, <c>O</c>, <c>U</c>.</item>
/// <item><b>Entropy</b>: at least 40 bits — at least 8 symbols — from a CSPRNG.</item>
/// <item><b>Hyphens</b>: presentational only; stripped before comparison.</item>
/// <item><b>Case</b>: comparison is case-insensitive, and on input the Crockford
///   decode aliases (<c>I</c>/<c>L</c> → <c>1</c>, <c>O</c> → <c>0</c>) are folded.</item>
/// </list>
/// The stateful rules — <b>single-use</b> and <b>rate-limiting</b> — are the
/// responsibility of the server's pending-interaction store (a code maps to a
/// pending entry that is consumed on use and whose validation attempts are
/// bounded); they are not pure functions and live with that state, not here.
/// </remarks>
public static class InteractionCode
{
    /// <summary>The Crockford base32 alphabet (no <c>I</c>, <c>L</c>, <c>O</c>, <c>U</c>).</summary>
    public const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>Minimum number of symbols required for ≥ 40 bits of entropy (8 × 5 bits).</summary>
    public const int MinimumSymbols = 8;

    /// <summary>
    /// Generate a fresh interaction code with at least <see cref="MinimumSymbols"/>
    /// symbols (≥ 40 bits of entropy) drawn from a cryptographically secure source.
    /// </summary>
    /// <param name="symbols">
    /// Number of Crockford base32 symbols. Must be at least <see cref="MinimumSymbols"/>;
    /// servers MAY use longer codes for higher-value interactions.
    /// </param>
    public static string Generate(int symbols = MinimumSymbols)
    {
        if (symbols < MinimumSymbols)
        {
            throw new ArgumentOutOfRangeException(
                nameof(symbols),
                $"An interaction code must carry at least 40 bits of entropy ({MinimumSymbols} symbols).");
        }

        var sb = new StringBuilder(symbols);
        // Rejection-free: each byte's low 5 bits index the 32-symbol alphabet, so
        // every symbol is uniformly distributed.
        Span<byte> buffer = symbols <= 64 ? stackalloc byte[symbols] : new byte[symbols];
        RandomNumberGenerator.Fill(buffer);
        foreach (var b in buffer)
        {
            sb.Append(Alphabet[b & 0x1F]);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Normalize a code for comparison: strip presentational hyphens, upper-case,
    /// and fold the Crockford glyph aliases (<c>I</c>/<c>L</c> → <c>1</c>,
    /// <c>O</c> → <c>0</c>). Returns <see langword="null"/> when, after
    /// normalization, any character is outside the Crockford alphabet.
    /// </summary>
    public static string? Normalize(string? code)
    {
        if (code is null)
        {
            return null;
        }

        var sb = new StringBuilder(code.Length);
        foreach (var raw in code)
        {
            if (raw == '-')
            {
                continue; // presentational grouping only
            }

            var c = char.ToUpperInvariant(raw);
            c = c switch
            {
                'I' or 'L' => '1',
                'O' => '0',
                _ => c,
            };

            if (Alphabet.IndexOf(c) < 0)
            {
                return null; // character outside the Crockford set
            }
            sb.Append(c);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Whether <paramref name="code"/> is a well-formed interaction code: it
    /// normalizes cleanly (Crockford alphabet after hyphen strip + glyph fold) and
    /// carries at least <see cref="MinimumSymbols"/> symbols of entropy.
    /// </summary>
    public static bool IsValid(string? code)
        => Normalize(code) is { Length: >= MinimumSymbols };

    /// <summary>
    /// Compare a user-entered code against the expected code per §Interaction Code
    /// Format: hyphen-insensitive, case-insensitive, and glyph-folded on both
    /// sides. Returns <see langword="false"/> if either side is malformed or
    /// carries fewer than <see cref="MinimumSymbols"/> symbols — a string too
    /// short to be a valid code (≥ 40 bits of entropy) MUST never match.
    /// </summary>
    public static bool Matches(string? expected, string? actual)
    {
        var a = Normalize(expected);
        var b = Normalize(actual);
        if (a is not { Length: >= MinimumSymbols } || b is not { Length: >= MinimumSymbols })
        {
            return false;
        }
        return string.Equals(a, b, StringComparison.Ordinal);
    }
}

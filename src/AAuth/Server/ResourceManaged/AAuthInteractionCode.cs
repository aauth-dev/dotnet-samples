using System;
using System.Security.Cryptography;
using System.Text;

namespace AAuth.Server;

/// <summary>
/// Generates and normalizes interaction codes per the AAuth spec
/// (§Interaction Code Format): Crockford base32, at least 40 bits of entropy,
/// case-insensitive comparison with the <c>I</c>/<c>L</c> → <c>1</c> and
/// <c>O</c> → <c>0</c> decode-alias folding, and optional presentational hyphens
/// stripped before comparison.
/// </summary>
public static class AAuthInteractionCode
{
    // Crockford base32 alphabet — omits the visually ambiguous I, L, O, U.
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>
    /// Generate a fresh code with at least <paramref name="symbols"/> Crockford
    /// base32 symbols (default 8 → 40 bits) drawn from a cryptographically secure
    /// random source. Each symbol carries a full 5 bits with no modulo bias
    /// (32 evenly divides 256).
    /// </summary>
    public static string Generate(int symbols = 8)
    {
        if (symbols < 8)
        {
            throw new ArgumentOutOfRangeException(
                nameof(symbols), "A code MUST carry at least 40 bits of entropy (>= 8 symbols).");
        }

        Span<byte> buffer = stackalloc byte[symbols];
        RandomNumberGenerator.Fill(buffer);
        var sb = new StringBuilder(symbols);
        foreach (var b in buffer)
        {
            sb.Append(Alphabet[b & 0x1F]);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Normalize a code for comparison: strip hyphens, uppercase, and fold the
    /// Crockford decode aliases (<c>I</c>/<c>L</c> → <c>1</c>, <c>O</c> → <c>0</c>).
    /// </summary>
    public static string Normalize(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        var sb = new StringBuilder(code.Length);
        foreach (var ch in code)
        {
            if (ch == '-')
            {
                continue;
            }
            var u = char.ToUpperInvariant(ch);
            u = u switch { 'I' or 'L' => '1', 'O' => '0', _ => u };
            sb.Append(u);
        }
        return sb.ToString();
    }

    /// <summary>Whether two codes are equal after normalization.</summary>
    public static bool Matches(string a, string b) =>
        string.Equals(Normalize(a), Normalize(b), StringComparison.Ordinal);
}

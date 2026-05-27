using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Crypto;

/// <summary>
/// File-based storage for <see cref="AAuthKey"/> instances under
/// <c>~/.aauth/keys/</c>. Each key is persisted as a JWK JSON document
/// (including the private <c>d</c> parameter).
/// </summary>
public sealed class FileKeyStore : IKeyStore
{
    private static readonly JsonSerializerOptions s_writerOptions = new() { WriteIndented = true };

    private readonly string _directory;

    /// <summary>The directory where keys are stored.</summary>
    public string Directory => _directory;

    /// <summary>Create a key store rooted at <paramref name="directory"/>.</summary>
    public FileKeyStore(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("Directory must be a non-empty path.", nameof(directory));
        }

        _directory = directory;
    }

    /// <summary>Create a key store at the default <c>~/.aauth/keys/</c> location.</summary>
    public static FileKeyStore Default()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new FileKeyStore(Path.Combine(home, ".aauth", "keys"));
    }

    /// <summary>Persist a key under <paramref name="name"/>.</summary>
    /// <remarks>
    /// On Unix-like systems the containing directory is created with mode
    /// <c>0700</c> and the file is created with mode <c>0600</c> at file
    /// creation time (no TOCTOU window between open and chmod) so the
    /// private key is never world-readable on disk. No equivalent
    /// restriction is currently applied on Windows (file ACLs are
    /// inherited from the parent directory — user profile defaults are
    /// typically already owner-only).
    /// </remarks>
    public void Save(string name, AAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateName(name);

        System.IO.Directory.CreateDirectory(_directory);
        TryRestrictUnixDirectoryPermissions(_directory);

        var path = PathFor(name);
        var jwk = key.ToPrivateJwk();
        var bytes = System.Text.Encoding.UTF8.GetBytes(jwk.ToJsonString(s_writerOptions));

        var options = new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
        };
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD())
        {
            // Create the file already owner-only; no umask race.
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        using var stream = new FileStream(path, options);
        stream.Write(bytes);
    }

    /// <summary>Load a key previously saved under <paramref name="name"/>.</summary>
    public AAuthKey Load(string name)
    {
        ValidateName(name);
        var path = PathFor(name);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"No key named '{name}' under {_directory}.", path);
        }

        return AAuthKey.FromJwkJson(File.ReadAllText(path));
    }

    /// <summary>True if a key with the given name is present.</summary>
    public bool Exists(string name)
    {
        ValidateName(name);
        return File.Exists(PathFor(name));
    }

    /// <summary>Load <paramref name="name"/> if present, otherwise generate, save, and return a new key.</summary>
    public AAuthKey LoadOrCreate(string name)
    {
        if (Exists(name))
        {
            return Load(name);
        }

        var key = AAuthKey.Generate();
        Save(name, key);
        return key;
    }

    // ── IKeyStore async implementation ──────────────────────────────────────

    /// <inheritdoc/>
    Task<IAAuthKey?> IKeyStore.LoadAsync(string keyId, CancellationToken ct)
    {
        ValidateName(keyId);
        var path = PathFor(keyId);
        if (!File.Exists(path))
            return Task.FromResult<IAAuthKey?>(null);

        IAAuthKey key = AAuthKey.FromJwkJson(File.ReadAllText(path));
        return Task.FromResult<IAAuthKey?>(key);
    }

    /// <inheritdoc/>
    Task IKeyStore.StoreAsync(string keyId, IAAuthKey key, CancellationToken ct)
    {
        if (key is AAuthKey concreteKey)
        {
            Save(keyId, concreteKey);
        }
        else
        {
            throw new ArgumentException("KeyStore only supports AAuthKey instances.", nameof(key));
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    Task IKeyStore.DeleteAsync(string keyId, CancellationToken ct)
    {
        ValidateName(keyId);
        var path = PathFor(keyId);
        if (File.Exists(path))
            File.Delete(path);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    Task<string[]> IKeyStore.ListAsync(CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(_directory))
            return Task.FromResult(Array.Empty<string>());

        var files = System.IO.Directory.GetFiles(_directory, "*.jwk.json");
        var names = files.Select(f => Path.GetFileNameWithoutExtension(
            Path.GetFileNameWithoutExtension(f))).ToArray();
        return Task.FromResult(names);
    }

    private string PathFor(string name) => Path.Combine(_directory, name + ".jwk.json");

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) ||
            name is "." or ".." ||
            name.IndexOfAny(s_forbiddenNameChars) >= 0 ||
            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new ArgumentException("Invalid key name.", nameof(name));
        }
    }

    // Always reject path separators (any platform) and the NUL byte. On
    // Linux, Path.GetInvalidFileNameChars() only excludes '/' and '\0', so
    // a name like "..\\foo" (with a literal backslash) or any name
    // containing the platform's *other* separator would otherwise slip
    // through and resolve outside the store.
    private static readonly char[] s_forbiddenNameChars =
        new[] { '/', '\\', '\0' };

    private static void TryRestrictUnixDirectoryPermissions(string path)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS() && !OperatingSystem.IsFreeBSD())
        {
            return;
        }
        // 0700 — owner-only access to the keys directory.
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
}

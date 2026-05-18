using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AAuth.Crypto;

/// <summary>
/// File-based storage for <see cref="AAuthKey"/> instances under
/// <c>~/.aauth/keys/</c>. Each key is persisted as a JWK JSON document
/// (including the private <c>d</c> parameter).
/// </summary>
public sealed class KeyStore
{
    private static readonly JsonSerializerOptions s_writerOptions = new() { WriteIndented = true };

    private readonly string _directory;

    /// <summary>The directory where keys are stored.</summary>
    public string Directory => _directory;

    /// <summary>Create a key store rooted at <paramref name="directory"/>.</summary>
    public KeyStore(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("Directory must be a non-empty path.", nameof(directory));
        }

        _directory = directory;
    }

    /// <summary>Create a key store at the default <c>~/.aauth/keys/</c> location.</summary>
    public static KeyStore Default()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new KeyStore(Path.Combine(home, ".aauth", "keys"));
    }

    /// <summary>Persist a key under <paramref name="name"/>.</summary>
    /// <remarks>
    /// On Unix-like systems the containing directory is created with mode
    /// <c>0700</c> and the file is written with mode <c>0600</c> so the
    /// private key is not world-readable. No equivalent restriction is
    /// applied on Windows in Phase 1 (file ACLs are inherited from the
    /// parent directory — user profile defaults are typically already
    /// owner-only).
    /// </remarks>
    public void Save(string name, AAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateName(name);

        System.IO.Directory.CreateDirectory(_directory);
        TryRestrictUnixPermissions(_directory, isDirectory: true);

        var path = PathFor(name);
        var jwk = key.ToPrivateJwk();
        File.WriteAllText(path, jwk.ToJsonString(s_writerOptions));
        TryRestrictUnixPermissions(path, isDirectory: false);
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

    private string PathFor(string name) => Path.Combine(_directory, name + ".jwk.json");

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) ||
            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new ArgumentException("Invalid key name.", nameof(name));
        }
    }

    private static void TryRestrictUnixPermissions(string path, bool isDirectory)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux) &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.OSX) &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
        {
            return;
        }

        // 0700 for directories, 0600 for files.
        var mode = isDirectory
            ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            : UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if (isDirectory)
        {
            File.SetUnixFileMode(path, mode);
        }
        else
        {
            File.SetUnixFileMode(path, mode);
        }
    }
}

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public static class NativeExports
{
    private static IncrementalHash? _sha1;

    [UnmanagedCallersOnly]
    public static int Init()
    {
        _sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        return 0;
    }

    [UnmanagedCallersOnly]
    public static unsafe void Update(byte* data, uint size)
    {
        _sha1?.AppendData(new ReadOnlySpan<byte>(data, (int)size));
    }

    [UnmanagedCallersOnly]
    public static unsafe int Get(byte* buffer)
    {
        if (_sha1 is null) return -1;
        _sha1.TryGetHashAndReset(new Span<byte>(buffer, 20), out _);
        return 0;
    }

    [UnmanagedCallersOnly]
    public static unsafe int GetPluginName(byte* buffer, int maxLength)
    {
        ReadOnlySpan<byte> name = "sha1dotnet"u8;
        int len = Math.Min(name.Length, maxLength - 1);
        name[..len].CopyTo(new Span<byte>(buffer, maxLength));
        buffer[len] = 0;
        return len;
    }
}
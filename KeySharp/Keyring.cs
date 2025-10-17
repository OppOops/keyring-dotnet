using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace KeySharp;

/// <summary>
/// Class used to interface with the OS keyring.
/// </summary>
public static class Keyring
{
    /// <summary>
    /// Save a password to the keyring.
    /// </summary>
    /// <param name="package">The package ID.</param>
    /// <param name="service">The service name.</param>
    /// <param name="username">The user name.</param>
    /// <param name="password">The password to save.</param>
    public static void SetPassword(string package, string service, string username, string password)
    {
        var nativePackage = AllocateNullTerminated(package);
        var nativeService = AllocateNullTerminated(service);
        var nativeUsername = AllocateNullTerminated(username);
        var nativePassword = AllocateNullTerminated(password);

        var ret = Glue.SetPassword(nativePackage, nativeService, nativeUsername, nativePassword);

        if (!ret)
        {
            ThrowLastError();
        }

        Free(nativePackage);
        Free(nativeService);
        Free(nativeUsername);
        Free(nativePassword);
    }

    /// <summary>
    /// Get a password from the keyring.
    /// </summary>
    /// <param name="package">The package ID.</param>
    /// <param name="service">The service name.</param>
    /// <param name="username">The user name.</param>
    /// <returns>The saved password.</returns>
    public static string GetPassword(string package, string service, string username)
    {
        var nativePackage = AllocateNullTerminated(package);
        var nativeService = AllocateNullTerminated(service);
        var nativeUsername = AllocateNullTerminated(username);

        var ret = Glue.GetPassword(nativePackage, nativeService, nativeUsername);

        if (ret == IntPtr.Zero)
        {
            ThrowLastError();
        }

        Free(nativePackage);
        Free(nativeService);
        Free(nativeUsername);

        return ReadString(ret);
    }

    /// <summary>
    /// Delete a password.
    /// </summary>
    /// <param name="package">The package ID.</param>
    /// <param name="service">The service name.</param>
    /// <param name="username">The user name.</param>
    public static void DeletePassword(string package, string service, string username)
    {
        var nativePackage = AllocateNullTerminated(package);
        var nativeService = AllocateNullTerminated(service);
        var nativeUsername = AllocateNullTerminated(username);

        var ret = Glue.DeletePassword(nativePackage, nativeService, nativeUsername);

        if (!ret)
        {
            ThrowLastError();
        }

        Free(nativePackage);
        Free(nativeService);
        Free(nativeUsername);
    }


    private static string ReadString(IntPtr data)
    {
        if (data == IntPtr.Zero) return null;
        return Marshal.PtrToStringUTF8(data);
    }

    private static void ThrowLastError()
    {
        var errorMsg = Glue.GetLastErrorMessage();
        var msgString = "Unknown error";

        if (errorMsg != IntPtr.Zero)
            msgString = ReadString(errorMsg);

        throw new KeyringException(Glue.GetLastError(), msgString);
    }

    private static IntPtr AllocateNullTerminated(string text)
    {
        if (text == null) return IntPtr.Zero;
        return Marshal.StringToCoTaskMemUTF8(text);
    }

    internal static void Free(IntPtr ptr)
    {
        if (ptr != IntPtr.Zero)
            Marshal.FreeCoTaskMem(ptr);
    }
}
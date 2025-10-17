using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace KeySharp;

internal static class Glue
{
    private static IntPtr _libraryHandle = IntPtr.Zero;
    private static bool _initialized = false;
    private static readonly object _lock = new();
    private static string _customLibraryPath = null;

    // Delegate types
    private delegate bool SetPasswordDelegate(IntPtr package, IntPtr service, IntPtr user, IntPtr password);
    private delegate IntPtr GetPasswordDelegate(IntPtr package, IntPtr service, IntPtr user);
    private delegate bool DeletePasswordDelegate(IntPtr package, IntPtr service, IntPtr user);
    private delegate IntPtr GetLastErrorMessageDelegate();
    private delegate ErrorType GetLastErrorDelegate();

    // Cached delegates
    private static SetPasswordDelegate _setPassword;
    private static GetPasswordDelegate _getPassword;
    private static DeletePasswordDelegate _deletePassword;
    private static GetLastErrorMessageDelegate _getLastErrorMessage;
    private static GetLastErrorDelegate _getLastError;

    /// <summary>
    /// Set a custom library path before first use (optional)
    /// </summary>
    public static void SetLibraryPath(string path)
    {
        lock (_lock)
        {
            if (_initialized)
                throw new InvalidOperationException("Library already loaded. Cannot change path.");
            _customLibraryPath = path;
        }
    }

    private static void Initialize()
    {
        if (_initialized) return;

        lock (_lock)
        {
            if (_initialized) return;

            try
            {
                if (_customLibraryPath != null)
                {
                    _libraryHandle = NativeLibrary.Load(_customLibraryPath);
                }
                else
                {
                    _libraryHandle = LoadPlatformLibrary();
                }

                LoadFunctionPointers();
                _initialized = true;
            }
            catch (Exception ex)
            {
                throw new DllNotFoundException($"Failed to load skeychain library: {ex.Message}", ex);
            }
        }
    }

    private static IntPtr LoadPlatformLibrary()
    {
        string libraryName;
        string rid;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            libraryName = "skeychain.dll";
            rid = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "win-x64",
                Architecture.X86 => "win-x86",
                Architecture.Arm64 => "win-arm64",
                _ => throw new PlatformNotSupportedException($"Unsupported Windows architecture: {RuntimeInformation.ProcessArchitecture}")
            };
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            libraryName = "libskeychain.so";
            rid = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "linux-x64",
                Architecture.Arm64 => "linux-arm64",
                Architecture.Arm => "linux-arm",
                _ => throw new PlatformNotSupportedException($"Unsupported Linux architecture: {RuntimeInformation.ProcessArchitecture}")
            };
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            libraryName = "libskeychain.dylib";
            rid = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "osx-x64",
                Architecture.Arm64 => "osx-arm64",
                _ => throw new PlatformNotSupportedException($"Unsupported macOS architecture: {RuntimeInformation.ProcessArchitecture}")
            };
        }
        else
        {
            throw new PlatformNotSupportedException("Unsupported platform");
        }

        // Try multiple possible locations
        var searchPaths = GetLibrarySearchPaths(libraryName, rid);

        foreach (var path in searchPaths)
        {
            if (File.Exists(path))
            {
                return NativeLibrary.Load(path);
            }
        }

        // If not found in specific paths, try default resolution
        try
        {
            return NativeLibrary.Load(libraryName);
        }
        catch (DllNotFoundException)
        {
            throw new DllNotFoundException(
                $"Could not find native library '{libraryName}' for RID '{rid}'. " +
                $"Searched paths:\n{string.Join("\n", searchPaths)}");
        }
    }

    private static string[] GetLibrarySearchPaths(string libraryName, string rid)
    {
        var assemblyLocation = Assembly.GetExecutingAssembly().Location;
        var assemblyDirectory = Path.GetDirectoryName(assemblyLocation) ?? Environment.CurrentDirectory;

        return new[]
        {
            // Published/NuGet package structure: runtimes/<rid>/native/
            Path.Combine(assemblyDirectory, "runtimes", rid, "native", libraryName),
            
            // Alternative NuGet structure
            Path.Combine(assemblyDirectory, "..", "runtimes", rid, "native", libraryName),
            
            // Development: Same directory as assembly
            Path.Combine(assemblyDirectory, libraryName),
            
            // Development: runtimes/<rid>/
            Path.Combine(assemblyDirectory, "runtimes", rid, libraryName),
            
            // Current directory
            Path.Combine(Environment.CurrentDirectory, libraryName),
            
            // Current directory with runtimes
            Path.Combine(Environment.CurrentDirectory, "runtimes", rid, "native", libraryName),
        };
    }

    private static void LoadFunctionPointers()
    {
        _setPassword = Marshal.GetDelegateForFunctionPointer<SetPasswordDelegate>(
            NativeLibrary.GetExport(_libraryHandle, "setPassword"));

        _getPassword = Marshal.GetDelegateForFunctionPointer<GetPasswordDelegate>(
            NativeLibrary.GetExport(_libraryHandle, "getPassword"));

        _deletePassword = Marshal.GetDelegateForFunctionPointer<DeletePasswordDelegate>(
            NativeLibrary.GetExport(_libraryHandle, "deletePassword"));

        _getLastErrorMessage = Marshal.GetDelegateForFunctionPointer<GetLastErrorMessageDelegate>(
            NativeLibrary.GetExport(_libraryHandle, "getLastErrorMessage"));

        _getLastError = Marshal.GetDelegateForFunctionPointer<GetLastErrorDelegate>(
            NativeLibrary.GetExport(_libraryHandle, "getLastError"));
    }

    public static bool SetPassword(IntPtr package, IntPtr service, IntPtr user, IntPtr password)
    {
        Initialize();
        return _setPassword(package, service, user, password);
    }

    public static IntPtr GetPassword(IntPtr package, IntPtr service, IntPtr user)
    {
        Initialize();
        return _getPassword(package, service, user);
    }

    public static bool DeletePassword(IntPtr package, IntPtr service, IntPtr user)
    {
        Initialize();
        return _deletePassword(package, service, user);
    }

    public static IntPtr GetLastErrorMessage()
    {
        Initialize();
        return _getLastErrorMessage();
    }

    public static ErrorType GetLastError()
    {
        Initialize();
        return _getLastError();
    }

    /// <summary>
    /// Unload the native library (optional cleanup)
    /// </summary>
    public static void Unload()
    {
        lock (_lock)
        {
            if (_libraryHandle != IntPtr.Zero)
            {
                NativeLibrary.Free(_libraryHandle);
                _libraryHandle = IntPtr.Zero;
                _initialized = false;
                _setPassword = null;
                _getPassword = null;
                _deletePassword = null;
                _getLastErrorMessage = null;
                _getLastError = null;
            }
        }
    }
}
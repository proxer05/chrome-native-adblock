using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ChromeNativeAdblock.Launcher;

/// <summary>
/// Grants Chrome's per-channel network-service LPAC (less-privileged AppContainer)
/// capability read/execute access to the native engine files. Chrome 155+ can run
/// the Network Service process inside the kNetworkServiceSandbox LPAC, whose token
/// is denied every path Chrome has not explicitly ACL'd, so a remote LoadLibraryW of
/// the engine DLL (and the filter file read by <c>cna_remote_initialize</c>) fails
/// until the capability SID is granted on those files. The sandbox itself stays on.
/// </summary>
internal static class ChromeLpacAccess
{
    private const string StableCapability = "lpacChromeStableNetworkSandbox";
    private const string BetaCapability = "lpacChromeBetaNetworkSandbox";
    private const string DevCapability = "lpacChromeDevNetworkSandbox";
    private const string CanaryCapability = "lpacChromeCanaryNetworkSandbox";
    private const string UnknownChannelCapability = "lpacChromeNetworkSandbox";

    /// <summary>Every Chrome network-sandbox capability name, one per channel.</summary>
    internal static IReadOnlyList<string> NetworkSandboxCapabilityNames { get; } =
    [
        StableCapability,
        BetaCapability,
        DevCapability,
        CanaryCapability,
        UnknownChannelCapability
    ];

    private static readonly object Sync = new();
    private static readonly HashSet<string> GrantedPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Optional diagnostics sink (the supervisor logs into the GUI console).</summary>
    internal static Action<string>? LogDiagnostics { get; set; }

    /// <summary>
    /// Grants every network-sandbox capability that may apply to the Chrome install
    /// running <paramref name="targetProcessId"/> read/execute access to the engine
    /// DLL and filter files (plus traversal on their ancestor directories).
    /// Safe to call repeatedly; each path is processed once per process lifetime.
    /// </summary>
    internal static void GrantEngineAccess(uint targetProcessId, string dllPath, string filterPath)
    {
        var capabilityNames = ResolveCapabilityNames(targetProcessId);
        foreach (var path in new[] { dllPath, filterPath })
        {
            GrantPath(path, capabilityNames);
        }
    }

    private static IReadOnlyList<string> ResolveCapabilityNames(uint processId)
    {
        var exePath = TryGetProcessImagePath(processId);
        if (exePath != null)
        {
            var normalized = exePath.Replace('/', '\\');
            if (normalized.Contains("\\Google\\Chrome SxS\\", StringComparison.OrdinalIgnoreCase))
            {
                return [CanaryCapability];
            }
            if (normalized.Contains("\\Google\\Chrome Dev\\", StringComparison.OrdinalIgnoreCase))
            {
                return [DevCapability];
            }
            if (normalized.Contains("\\Google\\Chrome Beta\\", StringComparison.OrdinalIgnoreCase))
            {
                return [BetaCapability];
            }
            if (normalized.Contains("\\Google\\Chrome\\", StringComparison.OrdinalIgnoreCase))
            {
                return [StableCapability];
            }
        }

        // Unknown install layout: grant every channel capability. ACEs for
        // capabilities that are not in the target token are simply never used.
        return NetworkSandboxCapabilityNames;
    }

    private static void GrantPath(string path, IReadOnlyList<string> capabilityNames)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            path = Path.GetFullPath(path);
        }
        catch (Exception)
        {
            return;
        }

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return;
        }

        GrantTarget(path, isDirectory: Directory.Exists(path) && !File.Exists(path), capabilityNames, warnOnFailure: true);

        // The LPAC token may lack bypass-traverse-checking, so also grant
        // traversal-only ACEs on every ancestor directory up to the drive root.
        // Ancestors the caller cannot modify (e.g. drive roots) are skipped.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var directory = Path.GetDirectoryName(path);
        while (!string.IsNullOrEmpty(directory) && seen.Add(directory))
        {
            GrantTarget(directory, isDirectory: true, capabilityNames, warnOnFailure: false);
            if (directory.Length <= 3 && Path.IsPathRooted(directory))
            {
                break; // drive root (e.g. D:\)
            }

            directory = Path.GetDirectoryName(directory.TrimEnd(Path.DirectorySeparatorChar));
        }
    }

    private static void GrantTarget(string path, bool isDirectory, IReadOnlyList<string> capabilityNames, bool warnOnFailure)
    {
        lock (Sync)
        {
            if (!GrantedPaths.Add(path))
            {
                return;
            }
        }

        foreach (var capabilityName in capabilityNames)
        {
            TryGrant(path, isDirectory, CapabilitySidToSddl(capabilityName), capabilityName, warnOnFailure);
        }
    }

    /// <summary>
    /// Derives the SDDL string of a named capability SID exactly like Chromium's
    /// base::win::Sid::FromNamedCapability: SHA-256 over the uppercased UTF-16
    /// name, appended as eight sub-authorities to S-1-15-3-1024.
    /// </summary>
    internal static string CapabilitySidToSddl(string capabilityName)
    {
        var hash = SHA256.HashData(Encoding.Unicode.GetBytes(capabilityName.ToUpperInvariant()));
        var parts = new string[13];
        parts[0] = "S";
        parts[1] = "1";
        parts[2] = "15";   // SECURITY_APP_PACKAGE_AUTHORITY
        parts[3] = "3";    // SECURITY_CAPABILITY_BASE_RID
        parts[4] = "1024"; // SECURITY_CAPABILITY_APP_RID
        for (var i = 0; i < 8; i++)
        {
            parts[5 + i] = BitConverter.ToUInt32(hash, i * 4).ToString();
        }
        return string.Join("-", parts);
    }

    private const int SeFileObject = 1;
    private const int DaclSecurityInformation = 4;
    private const uint GrantAccess = 1;
    private const int TrusteeIsSid = 4;
    private const uint GenericRead = 0x80000000;
    private const uint GenericExecute = 0x20000000;
    // FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE for ancestor directories:
    // enough to walk the path, without list-directory rights.
    private const uint DirectoryTraversal = 0x001000A0;

    private static void TryGrant(string path, bool isDirectory, string sid, string capabilityName, bool warnOnFailure)
    {
        try
        {
            // ConvertStringSidToSidW turns the S-1-15-3-1024-... string into the
            // real SID; LookupAccountName (used for TRUSTEE_IS_NAME trustees)
            // cannot resolve SDDL strings and fails with ERROR_NONE_MAPPED.
            if (!ConvertStringSidToSidW(sid, out var sidPtr))
            {
                throw new InvalidOperationException($"ConvertStringSidToSid failed with 0x{Marshal.GetLastWin32Error():X8}");
            }

            try
            {
                var entry = new ExplicitAccess
                {
                    AccessPermissions = isDirectory ? DirectoryTraversal : GenericRead | GenericExecute,
                    AccessMode = GrantAccess,
                    Inheritance = 0,
                    Trustee = new Trustee
                    {
                        TrusteeForm = TrusteeIsSid,
                        Name = sidPtr
                    }
                };

                var result = GetNamedSecurityInfoW(
                    path, SeFileObject, DaclSecurityInformation,
                    out _, out _, out var dacl, out _, out var securityDescriptor);
                if (result != 0)
                {
                    throw new InvalidOperationException($"GetNamedSecurityInfo failed with 0x{result:X8}");
                }

                try
                {
                    result = SetEntriesInAclW(1, in entry, dacl, out var newAcl);
                    if (result != 0)
                    {
                        throw new InvalidOperationException($"SetEntriesInAcl failed with 0x{result:X8}");
                    }

                    try
                    {
                        result = SetNamedSecurityInfoW(
                            path, SeFileObject, DaclSecurityInformation,
                            IntPtr.Zero, IntPtr.Zero, newAcl, IntPtr.Zero);
                        if (result != 0)
                        {
                            throw new InvalidOperationException($"SetNamedSecurityInfo failed with 0x{result:X8}");
                        }
                    }
                    finally
                    {
                        _ = LocalFree(newAcl);
                    }
                }
                finally
                {
                    _ = LocalFree(securityDescriptor);
                }
            }
            finally
            {
                _ = LocalFree(sidPtr);
            }
        }
        catch (Exception ex) when (warnOnFailure)
        {
            LogDiagnostics?.Invoke($"[LPAC] Could not grant '{capabilityName}' access to '{path}': {ex.Message}");
        }
        catch (Exception)
        {
            // Best effort for ancestors (e.g. drive roots owned by SYSTEM).
        }
    }

    private static string? TryGetProcessImagePath(uint processId)
    {
        const uint processQueryLimitedInformation = 0x1000;
        var handle = NativeMethods.OpenProcess(processQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new StringBuilder(1024);
            var size = (uint)buffer.Capacity;
            return QueryFullProcessImageNameW(handle, 0, buffer, ref size) ? buffer.ToString() : null;
        }
        finally
        {
            _ = NativeMethods.CloseHandle(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Trustee
    {
        public IntPtr MultipleTrustee;
        public int MultipleTrusteeOperation;
        public int TrusteeForm;
        public int TrusteeType;
        public IntPtr Name; // PSID when TrusteeForm is TRUSTEE_IS_SID
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ExplicitAccess
    {
        public uint AccessPermissions;
        public uint AccessMode;
        public uint Inheritance;
        public Trustee Trustee;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetNamedSecurityInfoW(
        string objectName,
        int objectType,
        int securityInfo,
        out IntPtr sidOwner,
        out IntPtr sidGroup,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int SetNamedSecurityInfoW(
        string objectName,
        int objectType,
        int securityInfo,
        IntPtr sidOwner,
        IntPtr sidGroup,
        IntPtr dacl,
        IntPtr sacl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSidToSidW(
        string stringSid,
        out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int SetEntriesInAclW(
        int entryCount,
        in ExplicitAccess entry,
        IntPtr oldAcl,
        out IntPtr newAcl);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr process,
        uint processNameFlags,
        StringBuilder exeName,
        ref uint size);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}

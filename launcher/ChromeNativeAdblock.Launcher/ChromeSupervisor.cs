using System.Diagnostics;
using System.Text;

namespace ChromeNativeAdblock.Launcher;

public sealed record ChromeSupervisorOptions(
    string? ChromePath = null,
    string? DllPath = null,
    string? FilterPath = null,
    string? UserDataDir = null,
    string[]? AdditionalArguments = null,
    bool EnableNativeAdblock = true,
    bool EnableMv2Enabler = true,
    bool AutoUpdateFilters = true,
    bool OpenExtensionsPage = false,
    int RemoteDebuggingPort = 0,
    bool Debug = false,
    Action<string>? LogCallback = null,
    Action<string, string>? BlockCallback = null,
    Action<uint>? StartedCallback = null);

public sealed class ChromeSupervisor : IDisposable
{
    private readonly ChromeSupervisorOptions _options;
    private readonly string _chromePath;
    private readonly string _dllPath;
    private readonly string _filterPath;
    private readonly CosmeticInjector _cosmeticInjector;
    private readonly LiveBlockMonitor? _liveBlockMonitor;
    private readonly HashSet<uint> _hookedNetworkProcesses = [];
    private readonly Lock _sync = new();
    private nint _cdpParentRead;
    private nint _cdpParentWrite;
    private (nint Read, nint Write) _chromePipeChildHandles;
    private volatile CdpPipeClient? _cdpClient;

    public LiveBlockMonitor? Monitor => _liveBlockMonitor;

    public ChromeSupervisor(ChromeSupervisorOptions? options = null)
    {
        _options = options ?? new ChromeSupervisorOptions();
        _chromePath = _options.ChromePath ?? ChromeInstallation.FindStableChrome();

        var root = FindRepositoryRoot();
        _dllPath = _options.DllPath ?? (File.Exists(Path.Combine(root, "target", "release", "chrome_native_adblock.dll"))
            ? Path.Combine(root, "target", "release", "chrome_native_adblock.dll")
            : Path.Combine(AppContext.BaseDirectory, "chrome_native_adblock.dll"));

        var repositoryFiltersDir = Path.Combine(root, "filters");
        var defaultFiltersDir = Directory.Exists(repositoryFiltersDir)
            ? repositoryFiltersDir
            : Path.Combine(AppContext.BaseDirectory, "filters");
        _filterPath = _options.FilterPath ?? Path.Combine(defaultFiltersDir, "combined_rules.txt");

        _cosmeticInjector = new CosmeticInjector();
        ChromeLpacAccess.LogDiagnostics = message => Log(message, ConsoleColor.Yellow);

        // Enable real-time console & live block monitor if not disabled and native adblock is active
        var enableMonitor = _options.EnableNativeAdblock &&
            !string.Equals(Environment.GetEnvironmentVariable("CNA_DISABLE_MONITOR"), "1", StringComparison.OrdinalIgnoreCase);
        if (enableMonitor)
        {
            _liveBlockMonitor = new LiveBlockMonitor(_cosmeticInjector)
            {
                BlockCallback = _options.BlockCallback
            };
        }
    }

    private static bool EnvFlag(string name) =>
        string.Equals(Environment.GetEnvironmentVariable(name), "1", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the given user data dir is the default profile directory of the
    /// detected Chrome channel; Google-Chrome-branded builds refuse remote
    /// debugging (port or pipe) on their default user data directory.
    /// </summary>
    private bool IsChannelDefaultUserDataDir(string? userDataDir)
    {
        if (string.IsNullOrWhiteSpace(userDataDir))
        {
            return true;
        }

        try
        {
            var normalized = _chromePath.Replace('/', '\\');
            var marker = normalized.IndexOf("\\Google\\", StringComparison.OrdinalIgnoreCase);
            if (marker < 0)
            {
                return false;
            }

            var afterGoogle = marker + "\\Google\\".Length;
            var application = normalized.IndexOf("\\Application\\", afterGoogle, StringComparison.OrdinalIgnoreCase);
            if (application < 0)
            {
                return false;
            }

            var channelDefault = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Google", normalized[afterGoogle..application], "User Data");
            return string.Equals(
                Path.GetFullPath(userDataDir).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(channelDefault).TrimEnd(Path.DirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>CNA_DISABLE_NETWORK_HOOK=1 skips native hook injection (for attribution).</summary>
    private static bool NetworkHookDisabled => EnvFlag("CNA_DISABLE_NETWORK_HOOK");

    /// <summary>CNA_DISABLE_COSMETIC=1 skips cosmetic/scriptlet injection (for attribution).</summary>
    private static bool CosmeticInjectionDisabled => EnvFlag("CNA_DISABLE_COSMETIC");

    /// <summary>
    /// CNA_DISABLE_CDP=1 launches Chrome without the CDP debug pipe entirely
    /// (for attribution). Unlike CNA_DISABLE_COSMETIC, which keeps the pipe
    /// attached but injects nothing, this removes the debugger from the
    /// process completely - cosmetic injection is impossible in this mode.
    /// </summary>
    private static bool CdpTransportDisabled => EnvFlag("CNA_DISABLE_CDP");

    private void Log(string message, ConsoleColor color = ConsoleColor.Gray)
    {
        lock (_sync)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ResetColor();
        }
        _options.LogCallback?.Invoke(message);
    }

    public async Task<int> RunAsync(CancellationToken cancellationToken = default)
    {
        var title = (_options.EnableNativeAdblock, _options.EnableMv2Enabler) switch
        {
            (true, true) => "Chrome Native Adblock (Adblock + Manifest V2)",
            (true, false) => "Chrome Native Adblock (RAM Hook & YouTube Bypass)",
            (false, true) => "Chrome Manifest V2 Enabler (RAM Patch)",
            _ => "Chrome Launcher (Passthrough)"
        };

        Log("==================================================", ConsoleColor.Cyan);
        Log($"     {title}     ", ConsoleColor.Cyan);
        Log("==================================================", ConsoleColor.Cyan);

        if (_liveBlockMonitor != null)
        {
            Log("[Supervisor] Real-time block monitor active. Live block stream enabled.", ConsoleColor.Green);
        }

        // 1. Resolve Chrome installation
        ChromeInstallation? installation = null;
        try
        {
            installation = ChromeInstallationFinder.Find(_chromePath);
            Log($"[Supervisor] Chrome detected: {installation.Version} ({installation.ExecutablePath})", ConsoleColor.Gray);

            // Every attribution run must be interpretable from its log alone:
            // state the isolation switches and the exact Chrome command line
            // up front, so a result can never be attributed to the wrong
            // configuration.
            var isolationSwitches = new List<string>();
            if (NetworkHookDisabled)
            {
                isolationSwitches.Add("CNA_DISABLE_NETWORK_HOOK");
            }
            if (CosmeticInjectionDisabled)
            {
                isolationSwitches.Add("CNA_DISABLE_COSMETIC");
            }
            if (CdpTransportDisabled)
            {
                isolationSwitches.Add("CNA_DISABLE_CDP");
            }
            if (isolationSwitches.Count > 0)
            {
                Log($"[Supervisor] Isolation switches active: {string.Join(", ", isolationSwitches)}.", ConsoleColor.Yellow);
            }
        }
        catch (Exception ex)
        {
            Log($"[Supervisor] Warning resolving Chrome installation details: {ex.Message}", ConsoleColor.Yellow);
        }

        // 2. Prepare user data dir & Chrome launch arguments
        var userDataArgument = _options.AdditionalArguments?
            .FirstOrDefault(a => a.StartsWith("--user-data-dir=", StringComparison.OrdinalIgnoreCase));
        var hasUserDataArg = userDataArgument != null;
        var effectiveUserDataDir = _options.UserDataDir;
        if (string.IsNullOrWhiteSpace(effectiveUserDataDir) && userDataArgument != null)
        {
            effectiveUserDataDir = userDataArgument[(userDataArgument.IndexOf('=') + 1)..].Trim().Trim('"');
        }
        if (string.IsNullOrWhiteSpace(effectiveUserDataDir) && !hasUserDataArg)
        {
            effectiveUserDataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ChromeNativeAdblock", "Profile");
            Directory.CreateDirectory(effectiveUserDataDir);
        }

        var chromeArgumentsList = new List<string>();
        var additionalArguments = _options.AdditionalArguments;
        var useCdpPipes = false;
        if (_options.EnableNativeAdblock)
        {
            // Speak CDP over --remote-debugging-pipe instead of
            // --remote-debugging-port. A TCP debug listener (even on an
            // ephemeral port) is detectable from the page - YouTube serves
            // empty stream responses to debugged clients and playback stalls
            // after the preloaded fragment. The pipe transport has no socket
            // and no DevToolsActivePort file, so nothing can be probed.
            // Chrome refuses remote debugging entirely when the user data dir
            // is the channel default, so pipes are only wired up for the
            // dedicated (or any non-default) profile.
            useCdpPipes = !IsChannelDefaultUserDataDir(effectiveUserDataDir) && !CdpTransportDisabled;
            if (useCdpPipes)
            {
                var sa = new NativeMethods.SecurityAttributes
                {
                    nLength = checked((uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.SecurityAttributes>()),
                    bInheritHandle = true
                };
                if (!NativeMethods.CreatePipe(out var chromeRead, out _cdpParentWrite, ref sa, 0) ||
                    !NativeMethods.CreatePipe(out _cdpParentRead, out var chromeWrite, ref sa, 0))
                {
                    throw NativeMethods.Error("CreatePipe failed for the CDP transport");
                }

                // Our ends must not leak into Chrome; only the two child ends
                // stay inheritable for CreateProcessW.
                _ = NativeMethods.SetHandleInformation(_cdpParentRead, NativeMethods.HandleFlagInherit, 0);
                _ = NativeMethods.SetHandleInformation(_cdpParentWrite, NativeMethods.HandleFlagInherit, 0);
                _chromePipeChildHandles = (chromeRead, chromeWrite);
                chromeArgumentsList.Add($"--remote-debugging-io-pipes={(uint)chromeRead.ToInt64()},{(uint)chromeWrite.ToInt64()}");
                chromeArgumentsList.Add("--remote-debugging-pipe");
            }
            else if (CdpTransportDisabled)
            {
                Log("[Supervisor] CNA_DISABLE_CDP=1 - CDP transport disabled; cosmetic injection is off for this session.", ConsoleColor.Yellow);
            }
            else
            {
                Log("[Supervisor] Chrome refuses remote debugging on the channel default profile - cosmetic injection is disabled for this session.", ConsoleColor.Yellow);
            }

            // Chrome 155+ enables the network-service sandbox on some builds
            // (Finch). The sandboxed Network Service process gets a
            // non-Microsoft-signed DLL block (MITIGATION_FORCE_MS_SIGNED_BINS)
            // and a dynamic-code prohibition, and Chrome forwards no switch to
            // sandboxed children that lifts either one - both make the
            // MinHook-based engine impossible to install. Disabling only the
            // network-service sandbox feature restores the exact Chrome <=153
            // model; every other sandbox (renderers, GPU, ...) stays enabled.
            const string networkSandboxFeature = "NetworkServiceSandbox";
            const string disableFeaturesPrefix = "--disable-features=";
            var userDisableFeatures = additionalArguments?.FirstOrDefault(
                a => a.StartsWith(disableFeaturesPrefix, StringComparison.OrdinalIgnoreCase));
            var userFeatures = userDisableFeatures?[disableFeaturesPrefix.Length..];
            // The flag exists solely so the hook DLL can load into the
            // network service. With CNA_DISABLE_NETWORK_HOOK=1 it changes
            // nothing but Chrome's own behavior, so skip it to keep
            // attribution runs (and hook-less sessions) pristine.
            var needsFeature = !NetworkHookDisabled && userFeatures?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Contains(networkSandboxFeature, StringComparer.OrdinalIgnoreCase) != true;
            if (needsFeature)
            {
                var merged = string.IsNullOrEmpty(userFeatures)
                    ? networkSandboxFeature
                    : $"{userFeatures},{networkSandboxFeature}";
                chromeArgumentsList.Add($"{disableFeaturesPrefix}{merged}");
                if (userDisableFeatures != null)
                {
                    // Replaced by the merged entry above.
                    additionalArguments = additionalArguments?
                        .Where(a => !a.StartsWith(disableFeaturesPrefix, StringComparison.OrdinalIgnoreCase))
                        .ToArray();
                }
            }
        }
        chromeArgumentsList.Add("--no-default-browser-check");
        chromeArgumentsList.Add("--no-first-run");

        if (!string.IsNullOrWhiteSpace(effectiveUserDataDir) && !hasUserDataArg)
        {
            chromeArgumentsList.Add($"--user-data-dir={Path.GetFullPath(effectiveUserDataDir)}");
        }

        if (additionalArguments is { Length: > 0 })
        {
            chromeArgumentsList.AddRange(additionalArguments);
        }

        if (_options.OpenExtensionsPage)
        {
            chromeArgumentsList.Add("chrome://extensions");
        }

        // 3. If Manifest V2 Enabler is active, repair profile preferences and locate RAM patch target
        PatchTarget? mv2PatchTarget = null;
        if (_options.EnableMv2Enabler)
        {
            if (installation == null)
            {
                installation = ChromeInstallationFinder.Find(_chromePath);
            }

            Log("[MV2] Scanning and repairing extension disabled states in profile Preferences...", ConsoleColor.Cyan);
            try
            {
                var repairResult = ChromeProfileRepair.RepairBeforeLaunch(installation, chromeArgumentsList);
                if (repairResult.ExtensionsReEnabled > 0)
                {
                    Log($"[MV2] Repaired {repairResult.ExtensionsReEnabled} disabled extension(s) across {repairResult.ProfilesChanged} profile(s).", ConsoleColor.Green);
                }
                else
                {
                    Log("[MV2] Profiles verified. All MV2 extensions in active state.", ConsoleColor.Gray);
                }
            }
            catch (Exception ex)
            {
                Log($"[MV2] Warning during profile repair: {ex.Message}", ConsoleColor.Yellow);
            }

            Log("[MV2] Analyzing chrome.dll for Manifest V2 Gate in RAM...", ConsoleColor.Cyan);
            var peImage = PeImage.Load(installation.DllPath);
            var locator = Mv2GateLocator.Locate(peImage);
            if (!locator.Success || locator.Target == null)
            {
                var errorMsg = $"MV2 Gate Locator failed: {string.Join("; ", locator.Diagnostics)}";
                Log($"[MV2] Error: {errorMsg}", ConsoleColor.Red);
                throw new InvalidOperationException(errorMsg);
            }

            mv2PatchTarget = locator.Target;
            Log($"[MV2] Located patch target ({mv2PatchTarget.RuleId}) at RVA 0x{mv2PatchTarget.PatchRva:X}.", ConsoleColor.Green);
        }

        // 4. If Native Adblock is active, ensure filters and preload cosmetic scripts
        NativeEngine? cosmeticEngine = null;
        Func<string, string> injectionScriptFactory = _ => string.Empty;
        if (_options.EnableNativeAdblock)
        {
            if (_options.AutoUpdateFilters)
            {
                try
                {
                    var filtersDir = Path.GetDirectoryName(_filterPath) ?? "filters";
                    var filterManager = new FilterManager(filtersDir);
                    Log("[Supervisor] Checking filter subscriptions...", ConsoleColor.Gray);
                    await filterManager.EnsureFiltersReadyAsync();
                    Log($"[Supervisor] Filters ready at: {_filterPath}", ConsoleColor.Gray);
                }
                catch (Exception ex)
                {
                    Log($"[Supervisor] Warning updating filters: {ex.Message}. Continuing with existing filters.", ConsoleColor.Yellow);
                }
            }

            if (!File.Exists(_dllPath))
            {
                throw new FileNotFoundException("Native DLL was not found. Please build the Rust crate first.", _dllPath);
            }
            if (!File.Exists(_filterPath))
            {
                throw new FileNotFoundException("Filter list was not found.", _filterPath);
            }

            cosmeticEngine = new NativeEngine(_dllPath);
            Log($"[Supervisor] Native Engine Version: {cosmeticEngine.GetVersion()}", ConsoleColor.Gray);
            cosmeticEngine.LoadFilterFile(_filterPath);
            injectionScriptFactory = url => CosmeticInjector.BuildInjectionScriptForUrl(cosmeticEngine, url);
            if (CosmeticInjectionDisabled)
            {
                injectionScriptFactory = _ => string.Empty;
                Log("[Supervisor] CNA_DISABLE_COSMETIC=1 - cosmetic/scriptlet injection is disabled for this session.", ConsoleColor.Yellow);
            }
            Log("[Supervisor] Cosmetic payloads will be generated from the exact URL of each tab.", ConsoleColor.Gray);
        }

        // 5. Launch Chrome process
        uint currentBrowserPid = 0;
        Process? browserProcess = null;

        if (_options.EnableMv2Enabler && mv2PatchTarget != null && installation != null)
        {
            Log($"[MV2] Launching Chrome with RAM patch interception: {installation.ExecutablePath}", ConsoleColor.Cyan);
            Log($"[MV2] Chrome arguments: {string.Join(' ', chromeArgumentsList.Select(ChromeDebugLauncher.QuoteArgument))}", ConsoleColor.Gray);
            var launchResult = ChromeDebugLauncher.Launch(
                installation,
                mv2PatchTarget,
                chromeArgumentsList,
                TimeSpan.FromSeconds(30),
                inheritHandles: useCdpPipes);

            CloseCdpChildHandles();
            currentBrowserPid = launchResult.ProcessId;
            Log($"[MV2] RAM patch successfully applied to chrome.dll in process PID: {launchResult.ProcessId} (Address: {launchResult.RemoteAddress}).", ConsoleColor.Green);
        }
        else
        {
            var argsString = string.Join(' ', chromeArgumentsList.Select(ChromeDebugLauncher.QuoteArgument));
            Log($"[Supervisor] Launching Chrome: {_chromePath} {argsString}", ConsoleColor.Cyan);

            currentBrowserPid = ChromeDebugLauncher.LaunchDetached(_chromePath, chromeArgumentsList, inheritHandles: useCdpPipes);
            CloseCdpChildHandles();
            Log($"[Supervisor] Chrome browser started with PID: {currentBrowserPid}", ConsoleColor.Green);
        }
        _options.StartedCallback?.Invoke(currentBrowserPid);


        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // 6. Background tasks for Native Adblock
        Task networkHookTask = Task.CompletedTask;
        Task cosmeticTask = Task.CompletedTask;

        if (_options.EnableNativeAdblock)
        {
            networkHookTask = Task.Run(() => MonitorNetworkServiceLoopAsync(() => currentBrowserPid, effectiveUserDataDir, cts.Token), cts.Token);
            cosmeticTask = Task.Run(() => RunCdpPipeLoopAsync(injectionScriptFactory, cts.Token), cts.Token);
        }

        // 7. Supervise session lifetime
        try
        {
            Log("[Supervisor] Active monitoring engaged. (Close Chrome or press Ctrl+C to terminate)", ConsoleColor.Cyan);

            var missedChecks = 0;
            while (!cts.Token.IsCancellationRequested)
            {
                bool initialRunning = false;
                if (browserProcess != null)
                {
                    try { initialRunning = !browserProcess.HasExited; } catch { }
                }
                else
                {
                    try
                    {
                        using var proc = Process.GetProcessById(checked((int)currentBrowserPid));
                        initialRunning = !proc.HasExited;
                    }
                    catch { }
                }

                var runningPids = ChromeProcesses.GetRunningChromePids(effectiveUserDataDir);
                if (runningPids.Count > 0)
                {
                    var mainPid = ChromeProcesses.FindMainBrowserPid(effectiveUserDataDir, currentBrowserPid);
                    if (mainPid.HasValue && mainPid.Value != currentBrowserPid)
                    {
                        currentBrowserPid = mainPid.Value;
                        if (_options.Debug)
                        {
                            Log($"[Supervisor] Updated active browser PID: {currentBrowserPid}", ConsoleColor.DarkGray);
                        }
                    }
                    missedChecks = 0;
                }
                else if (initialRunning)
                {
                    missedChecks = 0;
                }
                else
                {
                    var cdpActive = false;
                    if (_options.EnableNativeAdblock)
                    {
                        cdpActive = _cdpClient is { IsConnected: true };
                    }

                    if (cdpActive)
                    {
                        missedChecks = 0;
                    }
                    else
                    {
                        missedChecks++;
                        if (missedChecks >= 4)
                        {
                            Log("[Supervisor] All Chrome processes have exited.", ConsoleColor.Yellow);
                            break;
                        }
                    }
                }

                try
                {
                    await Task.Delay(500, cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            _liveBlockMonitor?.PrintSummary();
            return 0;
        }
        catch (OperationCanceledException)
        {
            Log("[Supervisor] Termination requested.", ConsoleColor.Yellow);
            KillAllChromeInProfile(effectiveUserDataDir, browserProcess);
            _liveBlockMonitor?.PrintSummary();
            return 0;
        }
        finally
        {
            cts.Cancel();
            // The summary prints before this runs, so a background task that
            // hangs or faults after Chrome exits would otherwise be invisible
            // (or hang the process with no output). Log both outcomes.
            try
            {
                await Task.WhenAll(networkHookTask, cosmeticTask);
                Log("[Supervisor] Background tasks completed.", ConsoleColor.DarkGray);
            }
            catch (Exception ex)
            {
                Log($"[Supervisor] Background task faulted during shutdown: {ex.GetType().Name}: {ex.Message}", ConsoleColor.Red);
            }
            browserProcess?.Dispose();
            cosmeticEngine?.Dispose();
        }
    }

    private static void KillAllChromeInProfile(string? userDataDir, Process? initialProcess)
    {
        try
        {
            if (initialProcess is { HasExited: false })
            {
                initialProcess.Kill(entireProcessTree: true);
            }
        }
        catch { }

        if (!string.IsNullOrWhiteSpace(userDataDir))
        {
            var pids = ChromeProcesses.GetRunningChromePids(userDataDir);
            foreach (var pid in pids)
            {
                try
                {
                    using var proc = Process.GetProcessById(checked((int)pid));
                    if (!proc.HasExited)
                    {
                        proc.Kill(entireProcessTree: true);
                    }
                }
                catch { }
            }
        }
    }

    private async Task MonitorNetworkServiceLoopAsync(Func<uint> getBrowserPid, string? userDataDir, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var browserPid = getBrowserPid();
                var networkPids = ChromeProcesses.FindNetworkServices(browserPid, userDataDir);
                foreach (var networkPid in networkPids)
                {
                    bool isNew;
                    lock (_sync)
                    {
                        isNew = _hookedNetworkProcesses.Add(networkPid);
                    }

                    if (isNew)
                    {
                        if (NetworkHookDisabled)
                        {
                            Log($"[Supervisor] CNA_DISABLE_NETWORK_HOOK=1 - skipping hook injection for PID {networkPid}.", ConsoleColor.Yellow);
                            continue;
                        }

                        Log($"[Supervisor] Detected Network Service process (PID: {networkPid}). Injecting native hook...", ConsoleColor.Yellow);

                        try
                        {
                            var result = InjectionSmoke.InjectExisting(
                                networkPid, _dllPath, _filterPath, installHook: true,
                                progress => Log(progress, ConsoleColor.DarkGray));
                            Log($"[Supervisor] Successfully hooked Network Service (PID: {result.ProcessId}). Hook Status: Active ({result.HookResolutionMode}).", ConsoleColor.Green);
                        }
                        catch (Exception ex)
                        {
                            Log($"[Supervisor] Failed to inject hook into PID {networkPid}: {ex.Message}", ConsoleColor.Red);
                            lock (_sync)
                            {
                                _hookedNetworkProcesses.Remove(networkPid);
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                // Continue polling, but say so - a monitor loop that throws
                // every iteration otherwise looks identical to one that finds
                // nothing (and nothing being hooked is exactly the failure we
                // are chasing).
                Log($"[Supervisor] Network service scan failed: {ex.GetType().Name}: {ex.Message}", ConsoleColor.Red);
            }

            try
            {
                await Task.Delay(250, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task RunCdpPipeLoopAsync(Func<string, string> injectionScriptFactory, CancellationToken cancellationToken)
    {
        // Entry/exit logging: a silently faulting CDP task is indistinguishable
        // from a pipe that was never wired up, and both look like "cosmetic
        // injection just doesn't happen". Log every path out of this loop.
        Log($"[CDP] Pipe loop starting (parent read=0x{_cdpParentRead:X}, write=0x{_cdpParentWrite:X}).", ConsoleColor.DarkGray);
        if (_cdpParentRead == 0 || _cdpParentWrite == 0)
        {
            Log("[CDP] Pipe transport not in use for this session.", ConsoleColor.DarkGray);
            return;
        }

        try
        {
            var client = new CdpPipeClient(_cdpParentRead, _cdpParentWrite, injectionScriptFactory)
            {
                LogDiagnostics = message => Log(message, ConsoleColor.Yellow)
            };
            client.ConsoleMessage += (domain, type, text) => _cosmeticInjector.RaiseConsoleMessage(domain, type, text);
            _cdpClient = client;
            client.StartAsync(cancellationToken);
            Log("[Supervisor] Connected to Chrome CDP over pipe. Cosmetic & scriptlet injection active on all tabs.", ConsoleColor.Magenta);

            await client.Completion;
            Log("[Supervisor] Chrome closed the CDP pipe.", ConsoleColor.DarkGray);
        }
        catch (OperationCanceledException)
        {
            Log("[CDP] Pipe loop cancelled.", ConsoleColor.DarkGray);
        }
        catch (Exception ex)
        {
            Log($"[CDP] Pipe loop faulted: {ex.GetType().Name}: {ex.Message}", ConsoleColor.Red);
        }
        finally
        {
            _cdpClient = null;
        }
    }

    /// <summary>
    /// Closes this process's copies of the pipe ends that were inherited by
    /// Chrome. Chrome keeps its own copies alive; dropping ours gives the pipe
    /// clean EOF semantics when Chrome exits.
    /// </summary>
    private void CloseCdpChildHandles()
    {
        if (_chromePipeChildHandles.Read != 0)
        {
            _ = NativeMethods.CloseHandle(_chromePipeChildHandles.Read);
            _chromePipeChildHandles.Read = 0;
        }
        if (_chromePipeChildHandles.Write != 0)
        {
            _ = NativeMethods.CloseHandle(_chromePipeChildHandles.Write);
            _chromePipeChildHandles.Write = 0;
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current != null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Cargo.toml")) ||
                Directory.Exists(Path.Combine(current.FullName, "filters")))
            {
                return current.FullName;
            }
            current = current.Parent;
        }
        return AppContext.BaseDirectory;
    }

    public void Dispose()
    {
        _cdpClient?.Dispose();
        if (_cdpParentRead != 0)
        {
            _ = NativeMethods.CloseHandle(_cdpParentRead);
            _cdpParentRead = 0;
        }
        if (_cdpParentWrite != 0)
        {
            _ = NativeMethods.CloseHandle(_cdpParentWrite);
            _cdpParentWrite = 0;
        }
        CloseCdpChildHandles();
        _liveBlockMonitor?.Dispose();
        _cosmeticInjector.Dispose();
    }
}

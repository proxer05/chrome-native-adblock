using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ChromeNativeAdblock.Launcher;

/// <summary>
/// Chrome DevTools Protocol client over --remote-debugging-pipe (ASCIIZ mode).
/// Speaks NUL-terminated JSON over the two anonymous pipes passed to Chrome via
/// --remote-debugging-io-pipes. Unlike --remote-debugging-port there is no TCP
/// listener and no DevToolsActivePort file, so nothing in the page can detect
/// the debug channel (YouTube serves empty stream responses to clients it
/// fingerprints as debugged, which stalls playback after the preloaded
/// fragment).
/// </summary>
internal sealed class CdpPipeClient : IDisposable
{
    private readonly FileStream _fromChrome;
    private readonly FileStream _toChrome;
    private readonly Func<string, string> _scriptFactory;
    private readonly object _writeLock = new();
    private readonly object _sessionLock = new();
    private readonly Dictionary<string, Session> _sessionsById = new(); // CDP sessionId -> info
    private readonly Dictionary<string, string> _sessionByTargetId = new(StringComparer.Ordinal);
    private int _nextId;
    private Task _readerTask = Task.CompletedTask;
    private volatile bool _connected;

    /// <summary>Raised for Runtime.consoleAPICalled events (domain, type, text).</summary>
    public event Action<string, string, string>? ConsoleMessage;

    /// <summary>Optional diagnostics sink (the supervisor logs into the GUI console).</summary>
    public Action<string>? LogDiagnostics { get; set; }

    public bool IsConnected => _connected;

    private sealed record Session(string TargetId, string Domain, string Url);

    /// <param name="fromChromeHandle">Our read end of the pipe Chrome writes to.</param>
    /// <param name="toChromeHandle">Our write end of the pipe Chrome reads from.</param>
    public CdpPipeClient(nint fromChromeHandle, nint toChromeHandle, Func<string, string> scriptFactory)
    {
        _fromChrome = new FileStream(
            new Microsoft.Win32.SafeHandles.SafeFileHandle(fromChromeHandle, ownsHandle: true),
            FileAccess.Read, bufferSize: 64 * 1024, isAsync: true);
        _toChrome = new FileStream(
            new Microsoft.Win32.SafeHandles.SafeFileHandle(toChromeHandle, ownsHandle: true),
            FileAccess.Write, bufferSize: 64 * 1024, isAsync: true);
        _scriptFactory = scriptFactory;
    }

    /// <summary>
    /// Starts the session: enables Target.setAutoAttach with flattened sessions so
    /// every page target (existing and new) is attached automatically, then injects
    /// the script for it (and on every future navigation via
    /// Page.addScriptToEvaluateOnNewDocument).
    /// </summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        Send(
            sessionId: null,
            "Target.setAutoAttach",
            new
            {
                autoAttach = true,
                waitForDebuggerOnStart = false,
                flatten = true,
                filter = new object[] { new { type = "page", exclude = false } }
            });
        _connected = true;
        _readerTask = Task.Run(() => ReadLoopAsync(cancellationToken), cancellationToken);
        return Task.CompletedTask;
    }

    /// <summary>Completes when Chrome closes the pipe (browser exit).</summary>
    public Task Completion => _readerTask;

    private async Task ReadLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        var message = new MemoryStream();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await _fromChrome.ReadAsync(buffer, cancellationToken);
                if (read == 0)
                {
                    break; // Chrome exited
                }

                for (var i = 0; i < read; i++)
                {
                    if (buffer[i] == 0)
                    {
                        if (message.Length > 0)
                        {
                            HandleMessage(Encoding.UTF8.GetString(message.ToArray()));
                        }
                        message.SetLength(0);
                    }
                    else
                    {
                        message.WriteByte(buffer[i]);
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
            // Pipe closed or broken - treat as disconnect.
        }
        finally
        {
            _connected = false;
        }
    }

    private void HandleMessage(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("method", out var methodProp) ||
                !root.TryGetProperty("params", out var paramsProp))
            {
                return;
            }

            var method = methodProp.GetString();
            var sessionId = root.TryGetProperty("sessionId", out var sessionProp)
                ? sessionProp.GetString()
                : null;

            switch (method)
            {
                case "Target.attachedToTarget":
                {
                    var newSessionId = paramsProp.TryGetProperty("sessionId", out var sid)
                        ? sid.GetString()
                        : null;
                    if (!paramsProp.TryGetProperty("targetInfo", out var info) || newSessionId == null)
                    {
                        return;
                    }

                    var type = info.TryGetProperty("type", out var typeProp) ? typeProp.GetString() : null;
                    if (!string.Equals(type, "page", StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }

                    var targetId = info.TryGetProperty("targetId", out var tid) ? tid.GetString() ?? newSessionId : newSessionId;
                    var url = info.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";
                    OnSessionAttached(newSessionId, targetId, url);
                    break;
                }
                case "Target.targetInfoChanged":
                {
                    if (!paramsProp.TryGetProperty("targetInfo", out var info))
                    {
                        return;
                    }

                    var targetId = info.TryGetProperty("targetId", out var tid) ? tid.GetString() : null;
                    var url = info.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";
                    OnTargetInfoChanged(targetId, url);
                    break;
                }
                case "Target.detachedFromTarget":
                {
                    var gone = paramsProp.TryGetProperty("sessionId", out var sid) ? sid.GetString() : null;
                    if (gone != null)
                    {
                        lock (_sessionLock)
                        {
                            if (_sessionsById.Remove(gone, out var removed))
                            {
                                _sessionByTargetId.Remove(removed.TargetId);
                            }
                        }
                    }
                    break;
                }
                case "Runtime.consoleAPICalled":
                {
                    var domain = "unknown";
                    if (sessionId != null)
                    {
                        lock (_sessionLock)
                        {
                            if (_sessionsById.TryGetValue(sessionId, out var session))
                            {
                                domain = session.Domain;
                            }
                        }
                    }

                    var type = paramsProp.TryGetProperty("type", out var typeProp)
                        ? typeProp.GetString() ?? "info"
                        : "info";
                    var text = "";
                    if (paramsProp.TryGetProperty("args", out var argsProp) && argsProp.ValueKind == JsonValueKind.Array)
                    {
                        var parts = new List<string>();
                        foreach (var arg in argsProp.EnumerateArray())
                        {
                            if (arg.TryGetProperty("value", out var valProp))
                            {
                                parts.Add(valProp.GetString() ?? valProp.ToString());
                            }
                            else if (arg.TryGetProperty("description", out var descProp))
                            {
                                parts.Add(descProp.GetString() ?? descProp.ToString());
                            }
                        }
                        text = string.Join(" ", parts);
                    }

                    ConsoleMessage?.Invoke(domain, type, text);
                    break;
                }
            }
        }
        catch (Exception)
        {
            // Ignore malformed frames.
        }
    }

    private void OnSessionAttached(string sessionId, string targetId, string url)
    {
        var domain = "unknown";
        try
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                domain = uri.Host;
            }
        }
        catch (Exception)
        {
        }

        lock (_sessionLock)
        {
            _sessionsById[sessionId] = new Session(targetId, domain, url);
            _sessionByTargetId[targetId] = sessionId;
        }

        var script = _scriptFactory(url);
        if (string.IsNullOrWhiteSpace(script))
        {
            return;
        }

        Send(sessionId, "Page.enable");
        Send(sessionId, "Page.addScriptToEvaluateOnNewDocument", new { source = script });
        Send(sessionId, "Runtime.enable");
        Send(sessionId, "Runtime.evaluate", new { expression = script });
    }

    private void OnTargetInfoChanged(string? targetId, string url)
    {
        if (targetId == null)
        {
            return;
        }

        string? sessionId;
        Session session;
        lock (_sessionLock)
        {
            if (!_sessionByTargetId.TryGetValue(targetId, out sessionId))
            {
                return;
            }
            if (!_sessionsById.TryGetValue(sessionId, out session!))
            {
                return;
            }
        }

        var domain = "unknown";
        try
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                domain = uri.Host;
            }
        }
        catch (Exception)
        {
        }

        lock (_sessionLock)
        {
            _sessionsById[sessionId] = session with { Domain = domain, Url = url };
        }

        // SPA navigations (history.pushState) do not create a new document, so
        // re-evaluate for the new URL - the generated script is host-guarded
        // and becomes a no-op on unrelated pages.
        if (!string.Equals(session.Url, url, StringComparison.Ordinal))
        {
            var script = _scriptFactory(url);
            if (!string.IsNullOrWhiteSpace(script))
            {
                Send(sessionId, "Runtime.evaluate", new { expression = script });
            }
        }
    }

    private void Send(string? sessionId, string method, object? @params = null)
    {
        var message = new JsonObject
        {
            ["id"] = Interlocked.Increment(ref _nextId),
            ["method"] = method,
        };
        if (sessionId != null)
        {
            message["sessionId"] = sessionId;
        }
        if (@params != null)
        {
            message["params"] = JsonSerializer.SerializeToNode(@params);
        }

        var bytes = Encoding.UTF8.GetBytes(message.ToJsonString());
        lock (_writeLock)
        {
            try
            {
                _toChrome.Write(bytes, 0, bytes.Length);
                _toChrome.WriteByte(0);
                _toChrome.Flush();
            }
            catch (Exception ex)
            {
                _connected = false;
                LogDiagnostics?.Invoke($"[CDP] Pipe write failed: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        _connected = false;
        try { _fromChrome.Dispose(); } catch (Exception) { }
        try { _toChrome.Dispose(); } catch (Exception) { }
    }
}

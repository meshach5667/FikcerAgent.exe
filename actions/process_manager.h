// ============================================================================
// FikcerAgent – Process Manager Interface
// ============================================================================
// Enumerates running processes, detects unresponsive processes, and can
// terminate + restart whitelisted applications.
//
// Platform backends:
//   • Windows : EnumProcesses, IsHungAppWindow, CreateProcessW
//   • macOS   : libproc (proc_listallpids / proc_pidpath), kill, posix_spawn
//
// Security model:
//   • Only processes whose executable name appears in the whitelist are
//     eligible for automatic restart.
//   • No arbitrary command execution – the launch call uses only the full
//     path previously obtained from the running process.
//   • DRY_RUN mode (config.h) prevents any kill/restart actions.
// ============================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#   include <Windows.h>
#endif

namespace fikcer::actions {

// ── Data structures ────────────────────────────────────────────────────────

/// Minimal information about a running process.
struct ProcessInfo {
    uint32_t    pid   = 0;
    std::string name;              ///< Executable file name (e.g. "notepad.exe").
    std::string fullPath;          ///< Full path to the executable.
    bool        isHung = false;    ///< Detected as "Not Responding".
};

/// Record of an automatic restart attempt.
struct RestartRecord {
    unsigned int attempts    = 0;  ///< How many times we tried to restart.
    uint64_t     lastAttempt = 0;  ///< Tick count of the last attempt.
};

/// Callback invoked when a hung process is detected.
using HungProcessCallback = std::function<void(const ProcessInfo&)>;

// ────────────────────────────────────────────────────────────────────────────
/// Manages process enumeration, hung-app detection, and safe restart.
// ────────────────────────────────────────────────────────────────────────────
class ProcessManager final {
public:
    ProcessManager()  = default;
    ~ProcessManager();

    ProcessManager(const ProcessManager&)            = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;
    ProcessManager(ProcessManager&&)                 = delete;
    ProcessManager& operator=(ProcessManager&&)      = delete;

    // ── Whitelist management ───────────────────────────────────────────────
    /// Add an executable name (case-insensitive) to the restart whitelist.
    void addToWhitelist(const std::string& exeName);

    /// Remove an executable name from the whitelist.
    void removeFromWhitelist(const std::string& exeName);

    /// @return true if the given name is whitelisted.
    [[nodiscard]] bool isWhitelisted(const std::string& exeName) const;

    /// @return A copy of the current whitelist.
    [[nodiscard]] std::unordered_set<std::string> whitelist() const;

    // ── Scanning ───────────────────────────────────────────────────────────
    /// Register a callback that fires for every hung process found.
    void setHungCallback(HungProcessCallback cb);

    /// Begin periodic scanning on a background thread.
    bool start(unsigned int intervalMs);

    /// Stop scanning and join the thread.
    void stop();

    /// @return true if the scanner thread is active.
    [[nodiscard]] bool isRunning() const noexcept;

    // ── Manual operations (can be called from any thread) ──────────────────
    /// Enumerate all visible processes.  Thread-safe.
    [[nodiscard]] std::vector<ProcessInfo> enumerateProcesses() const;

    /// Detect hung top-level windows and return their owning processes.
    [[nodiscard]] std::vector<ProcessInfo> detectHungProcesses() const;

    /// Terminate a process by PID.  Returns true on success.
    static bool terminateProcess(uint32_t pid);

    /// Restart a process given its full executable path.
    /// Returns the new PID, or 0 on failure.
    static uint32_t restartProcess(const std::string& exePath);

private:
    // ── Thread body ────────────────────────────────────────────────────────
    void scanLoop(unsigned int intervalMs);

    /// Attempt to auto-heal a single hung process.
    void handleHungProcess(const ProcessInfo& proc);

    // ── Helpers ────────────────────────────────────────────────────────────
    /// Normalise an executable name to lowercase for comparisons.
    [[nodiscard]] static std::string normaliseName(const std::string& name);

#ifdef _WIN32
    /// Callback passed to EnumWindows.
    static BOOL CALLBACK enumWindowsProc(HWND hwnd, LPARAM lParam);
#elif defined(__APPLE__)
    /// Heuristic: check if a process appears unresponsive (not accepting signals).
    static bool isProcessHung(pid_t pid);
#endif

    // ── State ──────────────────────────────────────────────────────────────
    std::thread                              thread_;
    std::atomic<bool>                        running_{false};
    HungProcessCallback                      hungCallback_;

    mutable std::mutex                       whitelistMutex_;
    std::unordered_set<std::string>          whitelist_;

    mutable std::mutex                       restartMutex_;
    std::unordered_map<std::string, RestartRecord> restartHistory_;
};

} // namespace fikcer::actions

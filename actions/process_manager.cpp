
// FikcerAgent – Process Manager Implementation

#include "actions/process_manager.h"
#include "config.h"
#include "utils/logger.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>

#ifdef _WIN32
#   include <Windows.h>
#   include <Psapi.h>      // EnumProcesses, GetModuleFileNameExW
#   include <TlHelp32.h>   // Fallback: CreateToolhelp32Snapshot
#elif defined(__APPLE__) || defined(__linux__)
#   include <cerrno>
#   include <csignal>
#   include <spawn.h>
#   ifdef __APPLE__
#       include <libproc.h>
#       include <sys/sysctl.h>
#   endif
    extern char** environ;  // POSIX: inherited environment for posix_spawn
#endif

namespace fikcer::actions {

using utils::Logger;

// ── Lifetime 

ProcessManager::~ProcessManager() {
    stop();
}

// ── Whitelist 

void ProcessManager::addToWhitelist(const std::string& exeName) {
    std::lock_guard lock(whitelistMutex_);
    whitelist_.insert(normaliseName(exeName));
    Logger::instance().info("Whitelist +: " + normaliseName(exeName));
}

void ProcessManager::removeFromWhitelist(const std::string& exeName) {
    std::lock_guard lock(whitelistMutex_);
    whitelist_.erase(normaliseName(exeName));
    Logger::instance().info("Whitelist -: " + normaliseName(exeName));
}

bool ProcessManager::isWhitelisted(const std::string& exeName) const {
    std::lock_guard lock(whitelistMutex_);
    return whitelist_.count(normaliseName(exeName)) > 0;
}

std::unordered_set<std::string> ProcessManager::whitelist() const {
    std::lock_guard lock(whitelistMutex_);
    return whitelist_;
}

// ── Scanning lifecycle ─────────────────────────────────────────────────────

void ProcessManager::setHungCallback(HungProcessCallback cb) {
    hungCallback_ = std::move(cb);
}

bool ProcessManager::start(unsigned int intervalMs) {
    if (running_.load(std::memory_order_acquire)) {
        return false;
    }

    running_.store(true, std::memory_order_release);

    try {
        thread_ = std::thread(&ProcessManager::scanLoop, this, intervalMs);
    } catch (const std::exception& ex) {
        running_.store(false, std::memory_order_release);
        Logger::instance().error(
            std::string("ProcessManager thread launch failed: ") + ex.what());
        return false;
    }

    Logger::instance().info("Process manager started.");
    return true;
}

void ProcessManager::stop() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    running_.store(false, std::memory_order_release);

    if (thread_.joinable()) {
        thread_.join();
    }
    Logger::instance().info("Process manager stopped.");
}

bool ProcessManager::isRunning() const noexcept {
    return running_.load(std::memory_order_acquire);
}

// ── Scan loop (runs on its own thread) 

void ProcessManager::scanLoop(unsigned int intervalMs) {
    using clock = std::chrono::steady_clock;

    while (running_.load(std::memory_order_acquire)) {
        auto hungList = detectHungProcesses();

        for (const auto& proc : hungList) {
            // Fire user callback.
            if (hungCallback_) {
                try { hungCallback_(proc); }
                catch (...) {
                    Logger::instance().error(
                        "Exception in hung-process callback.");
                }
            }

            // Attempt auto-heal if whitelisted.
            if (isWhitelisted(proc.name)) {
                handleHungProcess(proc);
            } else {
                Logger::instance().warn(
                    "Hung process NOT whitelisted – skipping: " + proc.name +
                    " (PID " + std::to_string(proc.pid) + ")");
            }
        }

        // Sleep in small chunks for responsive shutdown.
        const auto deadline =
            clock::now() + std::chrono::milliseconds(intervalMs);
        while (running_.load(std::memory_order_acquire) &&
               clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    }
}

// ── Auto-heal logic ────────────────────────────────────────────────────────

void ProcessManager::handleHungProcess(const ProcessInfo& proc) {
    auto& logger = Logger::instance();
    const std::string key = normaliseName(proc.name);

    // ── Check restart budget ───────────────────────────────────────────────
    {
        std::lock_guard lock(restartMutex_);
        auto& rec = restartHistory_[key];

        if (rec.attempts >= config::MAX_RESTART_ATTEMPTS) {
            logger.error(
                "Max restart attempts reached for " + proc.name +
                " – giving up.");
            return;
        }
    }

    // ── Dry-run guard 
    if constexpr (config::DRY_RUN) {
        logger.info("[DRY-RUN] Would terminate & restart: " + proc.name +
                    " (PID " + std::to_string(proc.pid) + ")");
        return;
    }

    // ── Validate executable path 
    if (proc.fullPath.empty()) {
        logger.error("Cannot restart " + proc.name + " – path unknown.");
        return;
    }

    // ── Terminate 
    logger.warn("Terminating hung process: " + proc.name +
                " (PID " + std::to_string(proc.pid) + ")");

    if (!terminateProcess(proc.pid)) {
        logger.error("Failed to terminate PID " + std::to_string(proc.pid));
        return;
    }

    // Grace period before restart.
    std::this_thread::sleep_for(
        std::chrono::milliseconds(config::RESTART_DELAY_MS));

    // ── Restart
    logger.info("Restarting: " + proc.fullPath);

    uint32_t newPid = restartProcess(proc.fullPath);
    if (newPid == 0) {
        logger.error("Failed to restart " + proc.fullPath);
    } else {
        logger.info("Restarted " + proc.name + " as PID " +
                    std::to_string(newPid));
    }

    // ── Update history
    {
        std::lock_guard lock(restartMutex_);
        auto& rec = restartHistory_[key];
        rec.attempts++;

#ifdef _WIN32
        rec.lastAttempt = GetTickCount64();
#else
        rec.lastAttempt = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
#endif
    }
}

// ── Process enumeration 

std::vector<ProcessInfo> ProcessManager::enumerateProcesses() const {
    std::vector<ProcessInfo> result;

#ifdef _WIN32
    // Use EnumProcesses for speed.
    DWORD pids[config::MAX_PROCESS_IDS]{};
    DWORD bytesReturned = 0;

    if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) {
        Logger::instance().error("EnumProcesses() failed.");
        return result;
    }

    const DWORD count = bytesReturned / sizeof(DWORD);
    result.reserve(count);

    for (DWORD i = 0; i < count; ++i) {
        if (pids[i] == 0) continue;   // Skip System Idle Process.

        HANDLE hProc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE, pids[i]);

        if (!hProc) continue;

        wchar_t exePath[MAX_PATH]{};
        DWORD pathLen = MAX_PATH;

        // QueryFullProcessImageNameW is more reliable than GetModuleFileNameEx.
        if (QueryFullProcessImageNameW(hProc, 0, exePath, &pathLen)) {
            ProcessInfo pi;
            pi.pid = pids[i];

            // Convert wide path to narrow UTF-8.
            int needed = WideCharToMultiByte(
                CP_UTF8, 0, exePath, static_cast<int>(pathLen),
                nullptr, 0, nullptr, nullptr);
            if (needed > 0) {
                pi.fullPath.resize(static_cast<std::size_t>(needed));
                WideCharToMultiByte(
                    CP_UTF8, 0, exePath, static_cast<int>(pathLen),
                    pi.fullPath.data(), needed, nullptr, nullptr);
            }

            // Extract file name from path.
            auto pos = pi.fullPath.find_last_of("\\/");
            pi.name = (pos != std::string::npos)
                        ? pi.fullPath.substr(pos + 1)
                        : pi.fullPath;

            result.push_back(std::move(pi));
        }

        CloseHandle(hProc);
    }

#elif defined(__APPLE__)
    // ── macOS: use libproc to enumerate all PIDs 
    int pidCount = proc_listallpids(nullptr, 0);
    if (pidCount <= 0) {
        Logger::instance().error("proc_listallpids() failed.");
        return result;
    }

    std::vector<pid_t> pids(static_cast<std::size_t>(pidCount));
    pidCount = proc_listallpids(pids.data(),
                                static_cast<int>(pids.size() * sizeof(pid_t)));
    if (pidCount <= 0) {
        return result;
    }

    result.reserve(static_cast<std::size_t>(pidCount));

    for (int i = 0; i < pidCount; ++i) {
        if (pids[static_cast<std::size_t>(i)] == 0) continue;

        char pathBuf[PROC_PIDPATHINFO_MAXSIZE]{};
        int ret = proc_pidpath(pids[static_cast<std::size_t>(i)],
                               pathBuf, sizeof(pathBuf));
        if (ret <= 0) continue;   // No permission or zombie.

        ProcessInfo pi;
        pi.pid      = static_cast<uint32_t>(pids[static_cast<std::size_t>(i)]);
        pi.fullPath = std::string(pathBuf);

        auto pos = pi.fullPath.find_last_of('/');
        pi.name  = (pos != std::string::npos)
                     ? pi.fullPath.substr(pos + 1)
                     : pi.fullPath;

        result.push_back(std::move(pi));
    }
#endif

    return result;
}

// ── Hung-process detection 

#ifdef _WIN32

/// Context passed through EnumWindows to collect hung windows.
struct HungWindowContext {
    std::vector<ProcessInfo>* results = nullptr;
};

BOOL CALLBACK ProcessManager::enumWindowsProc(HWND hwnd, LPARAM lParam) {
    // Skip invisible or child windows.
    if (!IsWindowVisible(hwnd)) return TRUE;

    // IsHungAppWindow is the most direct API for "Not Responding" detection.
    if (!IsHungAppWindow(hwnd)) return TRUE;

    auto* ctx = reinterpret_cast<HungWindowContext*>(lParam);
    if (!ctx || !ctx->results) return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return TRUE;

    // Avoid duplicates for multi-window apps.
    for (const auto& existing : *ctx->results) {
        if (existing.pid == pid) return TRUE;
    }

    // Resolve executable path.
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return TRUE;

    wchar_t exePath[MAX_PATH]{};
    DWORD pathLen = MAX_PATH;

    ProcessInfo pi;
    pi.pid    = pid;
    pi.isHung = true;

    if (QueryFullProcessImageNameW(hProc, 0, exePath, &pathLen)) {
        int needed = WideCharToMultiByte(
            CP_UTF8, 0, exePath, static_cast<int>(pathLen),
            nullptr, 0, nullptr, nullptr);
        if (needed > 0) {
            pi.fullPath.resize(static_cast<std::size_t>(needed));
            WideCharToMultiByte(
                CP_UTF8, 0, exePath, static_cast<int>(pathLen),
                pi.fullPath.data(), needed, nullptr, nullptr);
        }
        auto pos = pi.fullPath.find_last_of("\\/");
        pi.name  = (pos != std::string::npos)
                     ? pi.fullPath.substr(pos + 1)
                     : pi.fullPath;
    }

    CloseHandle(hProc);
    ctx->results->push_back(std::move(pi));
    return TRUE;   // Continue enumeration.
}

#endif // _WIN32

std::vector<ProcessInfo> ProcessManager::detectHungProcesses() const {
    std::vector<ProcessInfo> hung;

#ifdef _WIN32
    HungWindowContext ctx{&hung};
    EnumWindows(enumWindowsProc, reinterpret_cast<LPARAM>(&ctx));

#elif defined(__APPLE__)
    // macOS has no direct "IsHungAppWindow" equivalent.
    // Strategy: enumerate whitelisted processes and probe with kill(pid, 0).
    // If the process exists but is in an uninterruptible/zombie state, flag it.
    auto allProcs = enumerateProcesses();

    for (auto& proc : allProcs) {
        if (!isWhitelisted(proc.name)) continue;

        if (isProcessHung(static_cast<pid_t>(proc.pid))) {
            proc.isHung = true;
            hung.push_back(proc);
        }
    }
#endif

    return hung;
}

#ifdef __APPLE__
bool ProcessManager::isProcessHung(pid_t pid) {
    // Use sysctl to get the process kinfo and check for zombie/uninterruptible.
    struct kinfo_proc kp{};
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    size_t len = sizeof(kp);

    if (sysctl(mib, 4, &kp, &len, nullptr, 0) != 0 || len == 0) {
        return false;   // Can't query – not hung, just inaccessible.
    }

    // p_stat values: SIDL=1, SRUN=2, SSLEEP=3, SSTOP=4, SZOMB=5
    int state = kp.kp_proc.p_stat;

    // Zombie (5) or stopped (4) processes are considered hung.
    return (state == SZOMB || state == SSTOP);
}
#endif

// ── Terminate / Restart 

bool ProcessManager::terminateProcess(uint32_t pid) {
#ifdef _WIN32
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) {
        Logger::instance().error(
            "OpenProcess(TERMINATE) failed for PID " + std::to_string(pid) +
            " – error " + std::to_string(GetLastError()));
        return false;
    }

    BOOL ok = TerminateProcess(hProc, 1);
    DWORD err = GetLastError();
    CloseHandle(hProc);

    if (!ok) {
        Logger::instance().error(
            "TerminateProcess failed for PID " + std::to_string(pid) +
            " – error " + std::to_string(err));
        return false;
    }
    return true;

#elif defined(__APPLE__) || defined(__linux__)
    // First try SIGTERM (graceful), then SIGKILL if still alive.
    if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) {
        Logger::instance().error(
            "kill(SIGTERM) failed for PID " + std::to_string(pid) +
            " – errno " + std::to_string(errno));
        return false;
    }

    // Give the process 1 second to exit gracefully.
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Check if still alive.
    if (kill(static_cast<pid_t>(pid), 0) == 0) {
        // Still running – force kill.
        if (kill(static_cast<pid_t>(pid), SIGKILL) != 0) {
            Logger::instance().error(
                "kill(SIGKILL) failed for PID " + std::to_string(pid) +
                " – errno " + std::to_string(errno));
            return false;
        }
    }
    return true;
#else
    (void)pid;
    return false;
#endif
}

uint32_t ProcessManager::restartProcess(const std::string& exePath) {
    // ── Security check: path must look like a real executable ──────────────
    if (exePath.size() < 2) {
        Logger::instance().error("Refusing to launch suspicious path: " + exePath);
        return 0;
    }

#ifdef _WIN32
    // Convert UTF-8 path to wide string.
    int wideLen = MultiByteToWideChar(
        CP_UTF8, 0, exePath.c_str(), -1, nullptr, 0);
    if (wideLen <= 0) return 0;

    std::wstring widePath(static_cast<std::size_t>(wideLen), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, exePath.c_str(), -1, widePath.data(), wideLen);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION procInfo{};

    // CreateProcessW: lpApplicationName is the full path; no command-line
    // arguments are passed – this prevents arbitrary command injection.
    BOOL ok = CreateProcessW(
        widePath.c_str(),       // Application path (validated).
        nullptr,                // No command line – SECURITY.
        nullptr,                // Default process security.
        nullptr,                // Default thread security.
        FALSE,                  // Don't inherit handles.
        0,                      // Creation flags.
        nullptr,                // Inherit environment.
        nullptr,                // Inherit working directory.
        &si,
        &procInfo);

    if (!ok) {
        Logger::instance().error(
            "CreateProcessW failed – error " +
            std::to_string(GetLastError()));
        return 0;
    }

    uint32_t newPid = procInfo.dwProcessId;

    // We don't need the handles – close immediately to avoid leaks.
    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);

    return newPid;

#elif defined(__APPLE__) || defined(__linux__)
    // posix_spawn: safe process creation – no shell, no arbitrary args.
    pid_t childPid = 0;
    const char* argv[] = { exePath.c_str(), nullptr };

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    int ret = posix_spawn(
        &childPid,
        exePath.c_str(),
        nullptr,                // No file actions.
        &attr,
        const_cast<char* const*>(argv),
        environ);               // Inherit current environment.

    posix_spawnattr_destroy(&attr);

    if (ret != 0) {
        Logger::instance().error(
            "posix_spawn failed for " + exePath +
            " – error " + std::to_string(ret));
        return 0;
    }

    return static_cast<uint32_t>(childPid);
#else
    (void)exePath;
    return 0;
#endif
}

// ── Helpers

std::string ProcessManager::normaliseName(const std::string& name) {
    std::string out = name;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // namespace fikcer::actions

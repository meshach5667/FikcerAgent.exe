
// FikcerAgent – System Monitor Interface

// Periodically samples CPU and memory usage and exposes the latest readings
// in a thread-safe manner.
//
// Platform backends:
//   • Windows : GetSystemTimes (CPU), GlobalMemoryStatusEx (RAM)
//   • macOS   : host_processor_info (CPU), host_statistics64 (RAM)
//
// Design notes:
//   • The monitor runs on its own std::thread so it never blocks the main
//     loop or the process-manager thread.
//   • CPU usage is computed from the delta of idle / total ticks between
//     two consecutive snapshots.

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#   include <Windows.h>
#elif defined(__APPLE__)
#   include <mach/mach.h>
#endif

namespace fikcer::core {

// ── Snapshot struct ────────────────────────────────────────────────────────
/// A point-in-time reading of system resources.
struct SystemStats {
    double   cpuUsagePercent   = 0.0;   ///< Total CPU utilisation (0–100).
    double   memUsagePercent   = 0.0;   ///< Physical RAM utilisation (0–100).
    uint64_t memTotalBytes     = 0;     ///< Installed physical RAM.
    uint64_t memAvailableBytes = 0;     ///< Available physical RAM.
};

// ── Callback type ──────────────────────────────────────────────────────────
/// Called on the monitor thread each time a new snapshot is taken.
using StatsCallback = std::function<void(const SystemStats&)>;

// ────────────────────────────────────────────────────────────────────────────
/// System resource monitor.
///
/// Usage:
///   Monitor mon;
///   mon.setCallback([](const SystemStats& s) { /* print or log */ });
///   mon.start(5000);   // sample every 5 s
///   ...
///   mon.stop();
// ────────────────────────────────────────────────────────────────────────────
class Monitor final {
public:
    Monitor()  = default;
    ~Monitor();

    // Non-copyable, non-movable (owns a thread).
    Monitor(const Monitor&)            = delete;
    Monitor& operator=(const Monitor&) = delete;
    Monitor(Monitor&&)                 = delete;
    Monitor& operator=(Monitor&&)      = delete;

    /// Register a callback invoked on every sample.  Set before start().
    void setCallback(StatsCallback cb);

    /// Begin monitoring on a background thread.
    /// @param intervalMs  Milliseconds between samples.
    /// @return true if the thread was launched successfully.
    bool start(unsigned int intervalMs);

    /// Signal the monitor thread to stop and join it.
    void stop();

    /// @return The most recent snapshot (lock-free read).
    [[nodiscard]] SystemStats latestStats() const noexcept;

    /// @return true if the background thread is running.
    [[nodiscard]] bool isRunning() const noexcept;

private:
    // ── Thread entry point ─────────────────────────────────────────────────
    void workerLoop(unsigned int intervalMs);

    // ── Platform helpers ───────────────────────────────────────────────────
    /// Query memory (platform-specific).
    static bool queryMemory(SystemStats& out);

    /// Compute CPU % from delta of two snapshots.
    double computeCpuUsage();

#ifdef _WIN32
    FILETIME prevIdleTime_{};
    FILETIME prevKernelTime_{};
    FILETIME prevUserTime_{};
    bool     firstCpuSample_ = true;
#elif defined(__APPLE__)
    std::vector<uint64_t> prevPerCpuTicks_;   // [user,system,idle,nice] × N
    bool                  firstCpuSample_ = true;
#endif

    // ── State ──────────────────────────────────────────────────────────────
    std::thread         thread_;
    std::atomic<bool>   running_{false};
    StatsCallback       callback_;
    mutable std::mutex  statsMutex_;
    SystemStats         latest_;
};

} // namespace fikcer::core

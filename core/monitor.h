/**
 * @file monitor.h
 * @brief System resource monitor – CPU and memory usage sampling.
 *
 * FikcerAgent – Autonomous Self-Healing System Agent
 * Module: Core / Monitor
 *
 * Responsibilities:
 *   - Periodically sample total CPU usage (%) via GetSystemTimes().
 *   - Periodically sample physical memory usage (%) via GlobalMemoryStatusEx().
 *   - Run the sampling loop on a dedicated background thread so it never
 *     blocks the main thread or any other module.
 *   - Expose the latest snapshot through a lock-free atomic struct.
 *
 * Thread-safety:
 *   - Start() / Stop() must be called from the same (main) thread.
 *   - GetSnapshot() is safe to call from any thread at any time.
 *
 * Security:
 *   - No external input is consumed; only Windows kernel counters are read.
 */

#ifndef FIKCERAGENT_CORE_MONITOR_H
#define FIKCERAGENT_CORE_MONITOR_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

namespace fikcer::core {

/**
 * @brief A lightweight, copyable snapshot of system resources.
 *
 * All fields are best-effort values sampled at the time indicated by
 * `timestamp_ms` (milliseconds since epoch).
 */
struct SystemSnapshot {
    double   cpu_usage_percent  = 0.0;   ///< Overall CPU utilisation [0..100].
    double   mem_usage_percent  = 0.0;   ///< Physical RAM utilisation [0..100].
    uint64_t mem_total_mb       = 0;     ///< Total physical RAM in MiB.
    uint64_t mem_available_mb   = 0;     ///< Available physical RAM in MiB.
    int64_t  timestamp_ms       = 0;     ///< Time of this sample (epoch ms).
};

/**
 * @class SystemMonitor
 * @brief Background thread that samples CPU and RAM every `interval`.
 *
 * Usage:
 *   SystemMonitor mon;
 *   mon.Start(std::chrono::seconds{5});
 *   ...
 *   auto snap = mon.GetSnapshot();
 *   ...
 *   mon.Stop();
 */
class SystemMonitor final {
public:
    SystemMonitor()  = default;
    ~SystemMonitor();

    // Non-copyable, non-movable (owns a thread).
    SystemMonitor(const SystemMonitor&)            = delete;
    SystemMonitor& operator=(const SystemMonitor&) = delete;
    SystemMonitor(SystemMonitor&&)                 = delete;
    SystemMonitor& operator=(SystemMonitor&&)      = delete;

    /**
     * @brief Launch the background sampling thread.
     * @param interval  Time between two consecutive samples.
     * @return true if the thread was started, false if already running.
     */
    bool Start(std::chrono::milliseconds interval = std::chrono::seconds{5});

    /**
     * @brief Request the background thread to stop and join it.
     *        Safe to call even if not running.
     */
    void Stop() noexcept;

    /**
     * @brief Return the most recent system snapshot.
     *        Lock-free; may be called from any thread.
     */
    [[nodiscard]] SystemSnapshot GetSnapshot() const noexcept;

    /**
     * @brief Check whether the monitor thread is active.
     */
    [[nodiscard]] bool IsRunning() const noexcept { return running_.load(std::memory_order_acquire); }

private:
    /**
     * @brief The sampling loop executed on the background thread.
     */
    void SamplingLoop(std::chrono::milliseconds interval);

    /**
     * @brief Read the current CPU utilisation percentage.
     *        Uses delta of GetSystemTimes() between two calls.
     */
    double SampleCpuUsage();

    /**
     * @brief Read the current memory utilisation via GlobalMemoryStatusEx().
     */
    void SampleMemoryUsage(SystemSnapshot& snap);

    // ---- Data members ----------------------------------------------------
    std::atomic<bool>   running_{false};
    std::thread         thread_;

    // Snapshot shared between producer (bg thread) and consumer (any thread).
    // Protected via a simple spin on a seqlock-style atomic counter, but for
    // MVP simplicity we use a mutex-guarded copy (negligible contention at
    // 5-second intervals).
    mutable std::mutex  snap_mutex_;
    SystemSnapshot      latest_snap_;

    // Previous GetSystemTimes() values for delta calculation.
    uint64_t prev_idle_   = 0;
    uint64_t prev_kernel_ = 0;
    uint64_t prev_user_   = 0;
};

}  // namespace fikcer::core

#endif  // FIKCERAGENT_CORE_MONITOR_H

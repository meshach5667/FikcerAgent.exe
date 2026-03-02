// ============================================================================
// FikcerAgent – System Monitor Implementation
// ============================================================================
#include "core/monitor.h"
#include "utils/logger.h"

#include <chrono>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#   include <Windows.h>
#else
    // Stubs so the file compiles on non-Windows (CI, static analysis, etc.)
#endif

namespace fikcer::core {

// ── Lifetime ───────────────────────────────────────────────────────────────

Monitor::~Monitor() {
    stop();
}

// ── Public API ─────────────────────────────────────────────────────────────

void Monitor::setCallback(StatsCallback cb) {
    callback_ = std::move(cb);
}

bool Monitor::start(unsigned int intervalMs) {
    if (running_.load(std::memory_order_acquire)) {
        return false;   // Already running.
    }

    running_.store(true, std::memory_order_release);

    try {
        thread_ = std::thread(&Monitor::workerLoop, this, intervalMs);
    } catch (const std::exception& ex) {
        running_.store(false, std::memory_order_release);
        utils::Logger::instance().error(
            std::string("Monitor thread launch failed: ") + ex.what());
        return false;
    }

    utils::Logger::instance().info("System monitor started.");
    return true;
}

void Monitor::stop() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    running_.store(false, std::memory_order_release);

    if (thread_.joinable()) {
        thread_.join();
    }
    utils::Logger::instance().info("System monitor stopped.");
}

SystemStats Monitor::latestStats() const noexcept {
    std::lock_guard lock(statsMutex_);
    return latest_;
}

bool Monitor::isRunning() const noexcept {
    return running_.load(std::memory_order_acquire);
}

// ── Worker loop ────────────────────────────────────────────────────────────

void Monitor::workerLoop(unsigned int intervalMs) {
    using clock = std::chrono::steady_clock;
    auto& logger = utils::Logger::instance();

    while (running_.load(std::memory_order_acquire)) {
        SystemStats snap{};

        // ── Memory ─────────────────────────────────────────────────────────
        if (!queryMemory(snap)) {
            logger.warn("Failed to query memory stats.");
        }

        // ── CPU ────────────────────────────────────────────────────────────
#ifdef _WIN32
        snap.cpuUsagePercent = computeCpuUsage();
#else
        snap.cpuUsagePercent = 0.0;   // Stub for non-Windows builds.
#endif

        // ── Store latest ───────────────────────────────────────────────────
        {
            std::lock_guard lock(statsMutex_);
            latest_ = snap;
        }

        // ── Notify callback ────────────────────────────────────────────────
        if (callback_) {
            try {
                callback_(snap);
            } catch (...) {
                logger.error("Exception in monitor callback.");
            }
        }

        // ── Sleep in small increments so stop() is responsive ──────────────
        const auto deadline = clock::now() + std::chrono::milliseconds(intervalMs);
        while (running_.load(std::memory_order_acquire) && clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

// ── Platform: Memory ───────────────────────────────────────────────────────

bool Monitor::queryMemory(SystemStats& out) {
#ifdef _WIN32
    MEMORYSTATUSEX memInfo{};
    memInfo.dwLength = sizeof(memInfo);

    if (!GlobalMemoryStatusEx(&memInfo)) {
        return false;
    }

    out.memTotalBytes     = memInfo.ullTotalPhys;
    out.memAvailableBytes = memInfo.ullAvailPhys;
    out.memUsagePercent   = static_cast<double>(memInfo.dwMemoryLoad);

    return true;
#else
    // Non-Windows stub.
    (void)out;
    return false;
#endif
}

// ── Platform: CPU ──────────────────────────────────────────────────────────

#ifdef _WIN32

/// Converts a FILETIME to a 64-bit unsigned integer (100-ns ticks).
static inline uint64_t fileTimeToU64(const FILETIME& ft) noexcept {
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
            static_cast<uint64_t>(ft.dwLowDateTime);
}

double Monitor::computeCpuUsage() {
    FILETIME idleTime{}, kernelTime{}, userTime{};

    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        utils::Logger::instance().warn("GetSystemTimes() failed.");
        return 0.0;
    }

    if (firstCpuSample_) {
        // Need two samples to compute a delta – store the first and return 0.
        prevIdleTime_   = idleTime;
        prevKernelTime_ = kernelTime;
        prevUserTime_   = userTime;
        firstCpuSample_ = false;
        return 0.0;
    }

    const uint64_t idleDelta   = fileTimeToU64(idleTime)   - fileTimeToU64(prevIdleTime_);
    const uint64_t kernelDelta = fileTimeToU64(kernelTime) - fileTimeToU64(prevKernelTime_);
    const uint64_t userDelta   = fileTimeToU64(userTime)   - fileTimeToU64(prevUserTime_);

    // kernel time includes idle time on Windows.
    const uint64_t totalDelta = kernelDelta + userDelta;
    double cpuPercent = 0.0;
    if (totalDelta > 0) {
        cpuPercent = (1.0 - static_cast<double>(idleDelta) /
                            static_cast<double>(totalDelta)) * 100.0;
    }

    // Clamp to [0, 100].
    cpuPercent = (cpuPercent < 0.0) ? 0.0 : (cpuPercent > 100.0) ? 100.0 : cpuPercent;

    // Save for next delta.
    prevIdleTime_   = idleTime;
    prevKernelTime_ = kernelTime;
    prevUserTime_   = userTime;

    return cpuPercent;
}

#endif // _WIN32

} // namespace fikcer::core

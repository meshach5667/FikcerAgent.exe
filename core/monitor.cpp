
// FikcerAgent – System Monitor Implementation

#include "core/monitor.h"
#include "utils/logger.h"

#include <chrono>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#   include <Windows.h>
#elif defined(__APPLE__)
#   include <mach/mach.h>
#   include <mach/processor_info.h>
#   include <mach/mach_host.h>
#   include <sys/sysctl.h>
#   include <sys/types.h>
#endif

namespace fikcer::core {

//  Lifetime

Monitor::~Monitor() {
    stop();
}

//  Public API 

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

// Worker loop 

void Monitor::workerLoop(unsigned int intervalMs) {
    using clock = std::chrono::steady_clock;
    auto& logger = utils::Logger::instance();

    while (running_.load(std::memory_order_acquire)) {
        SystemStats snap{};

        // ── Memory 
        if (!queryMemory(snap)) {
            logger.warn("Failed to query memory stats.");
        }

        // ── CPU
        snap.cpuUsagePercent = computeCpuUsage();

        // ── Store lates
        {
            std::lock_guard lock(statsMutex_);
            latest_ = snap;
        }

        // ── Notify callback 
        if (callback_) {
            try {
                callback_(snap);
            } catch (...) {
                logger.error("Exception in monitor callback.");
            }
        }

        // ── Sleep in small increments so stop() is responsive
        const auto deadline = clock::now() + std::chrono::milliseconds(intervalMs);
        while (running_.load(std::memory_order_acquire) && clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

// ── Platform: Memory 
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

#elif defined(__APPLE__)
    // ── Total physical RAM via sysctl
    int mib[2] = { CTL_HW, HW_MEMSIZE };
    uint64_t totalMem = 0;
    size_t len = sizeof(totalMem);
    if (sysctl(mib, 2, &totalMem, &len, nullptr, 0) != 0) {
        return false;
    }
    out.memTotalBytes = totalMem;

    // ── Free / available RAM via Mach vm_statistics64
    vm_statistics64_data_t vmStat{};
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    kern_return_t kr = host_statistics64(
        mach_host_self(), HOST_VM_INFO64,
        reinterpret_cast<host_info64_t>(&vmStat), &count);

    if (kr != KERN_SUCCESS) {
        return false;
    }

    const uint64_t pageSize = static_cast<uint64_t>(vm_kernel_page_size);
    const uint64_t freeMem  = (static_cast<uint64_t>(vmStat.free_count) +
                               static_cast<uint64_t>(vmStat.inactive_count)) * pageSize;

    out.memAvailableBytes = freeMem;
    out.memUsagePercent   = (totalMem > 0)
        ? (1.0 - static_cast<double>(freeMem) / static_cast<double>(totalMem)) * 100.0
        : 0.0;

    return true;
#else
    (void)out;
    return false;
#endif
}

// ── Platform: CPU 

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
        prevIdleTime_   = idleTime;
        prevKernelTime_ = kernelTime;
        prevUserTime_   = userTime;
        firstCpuSample_ = false;
        return 0.0;
    }

    const uint64_t idleDelta   = fileTimeToU64(idleTime)   - fileTimeToU64(prevIdleTime_);
    const uint64_t kernelDelta = fileTimeToU64(kernelTime) - fileTimeToU64(prevKernelTime_);
    const uint64_t userDelta   = fileTimeToU64(userTime)   - fileTimeToU64(prevUserTime_);

    const uint64_t totalDelta = kernelDelta + userDelta;
    double cpuPercent = 0.0;
    if (totalDelta > 0) {
        cpuPercent = (1.0 - static_cast<double>(idleDelta) /
                            static_cast<double>(totalDelta)) * 100.0;
    }

    cpuPercent = (cpuPercent < 0.0) ? 0.0 : (cpuPercent > 100.0) ? 100.0 : cpuPercent;

    prevIdleTime_   = idleTime;
    prevKernelTime_ = kernelTime;
    prevUserTime_   = userTime;

    return cpuPercent;
}

#elif defined(__APPLE__)

double Monitor::computeCpuUsage() {
    // ── Collect per-CPU tick counts via Mach host_processor_info ────────────
    natural_t            numCPUs = 0;
    processor_info_array_t cpuInfo = nullptr;
    mach_msg_type_number_t numCpuInfo = 0;

    kern_return_t kr = host_processor_info(
        mach_host_self(), PROCESSOR_CPU_LOAD_INFO,
        &numCPUs, &cpuInfo, &numCpuInfo);

    if (kr != KERN_SUCCESS) {
        utils::Logger::instance().warn("host_processor_info() failed.");
        return 0.0;
    }

    // Pack into a flat vector: [user, system, idle, nice] per CPU.
    const std::size_t ticksPerCpu = CPU_STATE_MAX;
    std::vector<uint64_t> curTicks(numCPUs * ticksPerCpu, 0);

    for (natural_t i = 0; i < numCPUs; ++i) {
        auto* info = reinterpret_cast<processor_cpu_load_info_data_t*>(
            cpuInfo + static_cast<std::ptrdiff_t>(i * ticksPerCpu));
        curTicks[i * ticksPerCpu + CPU_STATE_USER]   = info->cpu_ticks[CPU_STATE_USER];
        curTicks[i * ticksPerCpu + CPU_STATE_SYSTEM] = info->cpu_ticks[CPU_STATE_SYSTEM];
        curTicks[i * ticksPerCpu + CPU_STATE_IDLE]   = info->cpu_ticks[CPU_STATE_IDLE];
        curTicks[i * ticksPerCpu + CPU_STATE_NICE]   = info->cpu_ticks[CPU_STATE_NICE];
    }

    // Deallocate the Mach-allocated array.
    vm_deallocate(mach_task_self(),
                  reinterpret_cast<vm_address_t>(cpuInfo),
                  numCpuInfo * sizeof(integer_t));

    if (firstCpuSample_) {
        prevPerCpuTicks_ = std::move(curTicks);
        firstCpuSample_  = false;
        return 0.0;
    }

    // ── Compute delta across all CPUs ──────────────────────────────────────
    uint64_t totalUser = 0, totalSystem = 0, totalIdle = 0, totalNice = 0;
    const std::size_t entries = std::min(curTicks.size(), prevPerCpuTicks_.size());
    const std::size_t cpuCount = entries / ticksPerCpu;

    for (std::size_t i = 0; i < cpuCount; ++i) {
        totalUser   += curTicks[i*ticksPerCpu + CPU_STATE_USER]
                     - prevPerCpuTicks_[i*ticksPerCpu + CPU_STATE_USER];
        totalSystem += curTicks[i*ticksPerCpu + CPU_STATE_SYSTEM]
                     - prevPerCpuTicks_[i*ticksPerCpu + CPU_STATE_SYSTEM];
        totalIdle   += curTicks[i*ticksPerCpu + CPU_STATE_IDLE]
                     - prevPerCpuTicks_[i*ticksPerCpu + CPU_STATE_IDLE];
        totalNice   += curTicks[i*ticksPerCpu + CPU_STATE_NICE]
                     - prevPerCpuTicks_[i*ticksPerCpu + CPU_STATE_NICE];
    }

    prevPerCpuTicks_ = std::move(curTicks);

    const uint64_t totalTicks = totalUser + totalSystem + totalIdle + totalNice;
    if (totalTicks == 0) return 0.0;

    double cpuPercent = static_cast<double>(totalUser + totalSystem + totalNice)
                      / static_cast<double>(totalTicks) * 100.0;

    cpuPercent = (cpuPercent < 0.0) ? 0.0 : (cpuPercent > 100.0) ? 100.0 : cpuPercent;
    return cpuPercent;
}

#else

double Monitor::computeCpuUsage() {
    return 0.0;   // Unsupported platform stub.
}

#endif

} // namespace fikcer::core

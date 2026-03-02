// ============================================================================
// FikcerAgent – AI Anomaly Detector Implementation
// ============================================================================
#include "ai/anomaly_detector.h"
#include "config.h"
#include "utils/logger.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>

#ifdef _WIN32
#   include <Windows.h>
#   include <Psapi.h>
#elif defined(__APPLE__)
#   include <libproc.h>
#   include <mach/mach.h>
#   include <sys/sysctl.h>
#endif

namespace fikcer::ai {

using utils::Logger;

// ============================================================================
// HeuristicAnalyzer
// ============================================================================

HeuristicAnalyzer::HeuristicAnalyzer() {
    // Use config thresholds as defaults.
    cpuSpikeThreshold_ = config::CPU_WARNING_THRESHOLD;
    memSpikeThreshold_ = config::MEMORY_WARNING_THRESHOLD;
}

std::vector<Anomaly> HeuristicAnalyzer::analyse(
    const core::SystemStats& stats,
    const std::vector<ProcessResourceInfo>& processes)
{
    // Record sample.
    Sample s;
    s.cpu      = stats.cpuUsagePercent;
    s.mem      = stats.memUsagePercent;
    s.memAvail = stats.memAvailableBytes;
    s.time     = std::chrono::steady_clock::now();

    history_.push_back(s);
    if (history_.size() > MAX_HISTORY) {
        history_.pop_front();
    }

    std::vector<Anomaly> anomalies;

    detectCpuSpike(stats, anomalies);
    detectCpuRamp(stats, anomalies);
    detectMemorySpike(stats, anomalies);
    detectMemoryLeak(stats, anomalies);
    detectProcessHogs(processes, anomalies);
    detectSystemOverload(stats, anomalies);

    return anomalies;
}

// ── Tuning setters ─────────────────────────────────────────────────────────

void HeuristicAnalyzer::setCpuSpikeThreshold(double p, unsigned int n) {
    cpuSpikeThreshold_ = p; cpuSpikeConsecutive_ = n;
}
void HeuristicAnalyzer::setMemorySpikeThreshold(double p, unsigned int n) {
    memSpikeThreshold_ = p; memSpikeConsecutive_ = n;
}
void HeuristicAnalyzer::setCpuRampThreshold(double d) { cpuRampDelta_ = d; }
void HeuristicAnalyzer::setMemoryLeakWindowSize(unsigned int n) { memLeakWindow_ = n; }
void HeuristicAnalyzer::setProcessCpuHogThreshold(double p) { processCpuHogThreshold_ = p; }
void HeuristicAnalyzer::setProcessMemHogBytes(uint64_t b) { processMemHogBytes_ = b; }

// ── Detection: CPU Spike ───────────────────────────────────────────────────

void HeuristicAnalyzer::detectCpuSpike(
    const core::SystemStats& stats, std::vector<Anomaly>& out)
{
    if (stats.cpuUsagePercent >= cpuSpikeThreshold_) {
        cpuSpikeCounter_++;
    } else {
        cpuSpikeCounter_ = 0;
    }

    if (cpuSpikeCounter_ >= cpuSpikeConsecutive_) {
        Anomaly a;
        a.type        = AnomalyType::CPU_SPIKE;
        a.severity    = computeSeverity(stats.cpuUsagePercent, cpuSpikeThreshold_);
        a.metricValue = stats.cpuUsagePercent;
        a.timestamp   = std::chrono::steady_clock::now();

        std::ostringstream oss;
        oss << "CPU usage at " << std::fixed << std::setprecision(1)
            << stats.cpuUsagePercent << "% for " << cpuSpikeCounter_
            << " consecutive samples (threshold: " << cpuSpikeThreshold_ << "%)";
        a.description = oss.str();
        a.recommendation = "Identify top CPU-consuming processes. "
                           "Consider terminating non-essential workloads.";

        out.push_back(std::move(a));
    }
}

// ── Detection: CPU Ramp ────────────────────────────────────────────────────

void HeuristicAnalyzer::detectCpuRamp(
    const core::SystemStats& stats, std::vector<Anomaly>& out)
{
    if (history_.size() < 2) return;

    double prevCpu = history_[history_.size() - 2].cpu;
    double delta   = stats.cpuUsagePercent - prevCpu;

    if (delta >= cpuRampDelta_) {
        Anomaly a;
        a.type        = AnomalyType::CPU_RAMP;
        a.severity    = (delta >= cpuRampDelta_ * 2.0) ? Severity::HIGH : Severity::MEDIUM;
        a.metricValue = delta;
        a.timestamp   = std::chrono::steady_clock::now();

        std::ostringstream oss;
        oss << "CPU usage jumped +" << std::fixed << std::setprecision(1)
            << delta << "% in one sample interval (" << prevCpu
            << "% -> " << stats.cpuUsagePercent << "%)";
        a.description = oss.str();
        a.recommendation = "Sudden CPU spike detected. Check for recently "
                           "launched compute-intensive processes.";

        out.push_back(std::move(a));
    }
}

// ── Detection: Memory Spike ────────────────────────────────────────────────

void HeuristicAnalyzer::detectMemorySpike(
    const core::SystemStats& stats, std::vector<Anomaly>& out)
{
    if (stats.memUsagePercent >= memSpikeThreshold_) {
        memSpikeCounter_++;
    } else {
        memSpikeCounter_ = 0;
    }

    if (memSpikeCounter_ >= memSpikeConsecutive_) {
        Anomaly a;
        a.type        = AnomalyType::MEMORY_SPIKE;
        a.severity    = computeSeverity(stats.memUsagePercent, memSpikeThreshold_);
        a.metricValue = stats.memUsagePercent;
        a.timestamp   = std::chrono::steady_clock::now();

        std::ostringstream oss;
        oss << "Memory usage at " << std::fixed << std::setprecision(1)
            << stats.memUsagePercent << "% for " << memSpikeCounter_
            << " consecutive samples";
        a.description = oss.str();
        a.recommendation = "Identify top memory-consuming processes. "
                           "Consider closing heavy applications or increasing swap.";

        out.push_back(std::move(a));
    }
}

// ── Detection: Memory Leak ─────────────────────────────────────────────────

void HeuristicAnalyzer::detectMemoryLeak(
    const core::SystemStats& /*stats*/, std::vector<Anomaly>& out)
{
    if (history_.size() < memLeakWindow_) return;

    // Check if available memory has been monotonically decreasing over
    // the last memLeakWindow_ samples.
    bool monotonic = true;
    auto it = history_.end() - static_cast<std::ptrdiff_t>(memLeakWindow_);

    uint64_t prev = it->memAvail;
    ++it;
    for (; it != history_.end(); ++it) {
        if (it->memAvail >= prev) {
            monotonic = false;
            break;
        }
        prev = it->memAvail;
    }

    if (monotonic) {
        auto start = history_.end() - static_cast<std::ptrdiff_t>(memLeakWindow_);
        uint64_t lost = start->memAvail - history_.back().memAvail;

        Anomaly a;
        a.type        = AnomalyType::MEMORY_LEAK;
        a.severity    = (lost > 512ULL * 1024 * 1024) ? Severity::HIGH : Severity::MEDIUM;
        a.metricValue = static_cast<double>(lost) / (1024.0 * 1024.0);
        a.timestamp   = std::chrono::steady_clock::now();

        std::ostringstream oss;
        oss << "Available memory has decreased monotonically over "
            << memLeakWindow_ << " samples (lost ~"
            << std::fixed << std::setprecision(0)
            << a.metricValue << " MB)";
        a.description = oss.str();
        a.recommendation = "Possible memory leak detected. Identify processes "
                           "with growing RSS and consider restarting them.";

        out.push_back(std::move(a));
    }
}

// ── Detection: Process Hogs ────────────────────────────────────────────────

void HeuristicAnalyzer::detectProcessHogs(
    const std::vector<ProcessResourceInfo>& procs, std::vector<Anomaly>& out)
{
    for (const auto& p : procs) {
        // CPU hog
        if (p.cpuPercent >= processCpuHogThreshold_) {
            Anomaly a;
            a.type           = AnomalyType::PROCESS_CPU_HOG;
            a.severity       = computeSeverity(p.cpuPercent, processCpuHogThreshold_);
            a.metricValue    = p.cpuPercent;
            a.relatedPid     = p.pid;
            a.relatedProcess = p.name;
            a.timestamp      = std::chrono::steady_clock::now();

            std::ostringstream oss;
            oss << "Process '" << p.name << "' (PID " << p.pid
                << ") using " << std::fixed << std::setprecision(1)
                << p.cpuPercent << "% CPU";
            a.description = oss.str();
            a.recommendation = "Consider lowering process priority or "
                               "terminating if non-essential.";

            out.push_back(std::move(a));
        }

        // Memory hog
        if (p.residentBytes >= processMemHogBytes_) {
            Anomaly a;
            a.type           = AnomalyType::PROCESS_MEM_HOG;
            a.severity       = Severity::HIGH;
            a.metricValue    = static_cast<double>(p.residentBytes) / (1024.0*1024.0);
            a.relatedPid     = p.pid;
            a.relatedProcess = p.name;
            a.timestamp      = std::chrono::steady_clock::now();

            std::ostringstream oss;
            oss << "Process '" << p.name << "' (PID " << p.pid
                << ") using " << std::fixed << std::setprecision(0)
                << a.metricValue << " MB resident memory";
            a.description = oss.str();
            a.recommendation = "Investigate for memory leaks. Consider "
                               "restarting if memory usage is abnormal.";

            out.push_back(std::move(a));
        }
    }
}

// ── Detection: System Overload ─────────────────────────────────────────────

void HeuristicAnalyzer::detectSystemOverload(
    const core::SystemStats& stats, std::vector<Anomaly>& out)
{
    if (stats.cpuUsagePercent >= cpuSpikeThreshold_ &&
        stats.memUsagePercent >= memSpikeThreshold_)
    {
        Anomaly a;
        a.type        = AnomalyType::SYSTEM_OVERLOAD;
        a.severity    = Severity::CRITICAL;
        a.metricValue = std::max(stats.cpuUsagePercent, stats.memUsagePercent);
        a.timestamp   = std::chrono::steady_clock::now();

        std::ostringstream oss;
        oss << "SYSTEM OVERLOAD: CPU=" << std::fixed << std::setprecision(1)
            << stats.cpuUsagePercent << "% RAM=" << stats.memUsagePercent << "%";
        a.description = oss.str();
        a.recommendation = "System is critically overloaded. Terminate "
                           "non-essential processes immediately. Consider "
                           "emergency resource reclamation.";

        out.push_back(std::move(a));
    }
}

// ── Severity computation ───────────────────────────────────────────────────

Severity HeuristicAnalyzer::computeSeverity(double value, double threshold) const {
    double overshoot = value - threshold;
    if (overshoot >= 8.0)  return Severity::CRITICAL;
    if (overshoot >= 5.0)  return Severity::HIGH;
    if (overshoot >= 2.0)  return Severity::MEDIUM;
    return Severity::LOW;
}

// ============================================================================
// AnomalyDetector (orchestrator)
// ============================================================================

AnomalyDetector::AnomalyDetector()
    : analyzer_(std::make_unique<HeuristicAnalyzer>())
{}

void AnomalyDetector::setAnalyzer(std::unique_ptr<Analyzer> analyzer) {
    std::lock_guard lock(mutex_);
    analyzer_ = std::move(analyzer);
}

void AnomalyDetector::setCallback(AnomalyCallback cb) {
    std::lock_guard lock(mutex_);
    callback_ = std::move(cb);
}

std::vector<Anomaly> AnomalyDetector::feed(
    const core::SystemStats& stats,
    const std::vector<ProcessResourceInfo>& processes)
{
    std::vector<Anomaly> results;

    {
        std::lock_guard lock(mutex_);
        if (analyzer_) {
            results = analyzer_->analyse(stats, processes);
        }
    }

    // Fire callback outside the lock to avoid deadlocks.
    if (!results.empty() && callback_) {
        try {
            callback_(results);
        } catch (...) {
            Logger::instance().error("Exception in anomaly callback.");
        }
    }

    return results;
}

// ============================================================================
// Per-process resource sampling (platform-specific)
// ============================================================================

std::vector<ProcessResourceInfo> AnomalyDetector::sampleProcessResources() {
    std::vector<ProcessResourceInfo> result;

#ifdef __APPLE__
    // Get total CPU core count for percentage calculation.
    int cpuCount = 1;
    {
        int mib[2] = { CTL_HW, HW_NCPU };
        size_t len = sizeof(cpuCount);
        sysctl(mib, 2, &cpuCount, &len, nullptr, 0);
        if (cpuCount < 1) cpuCount = 1;
    }

    // Enumerate all PIDs.
    int pidCount = proc_listallpids(nullptr, 0);
    if (pidCount <= 0) return result;

    std::vector<pid_t> pids(static_cast<size_t>(pidCount));
    pidCount = proc_listallpids(pids.data(),
                                static_cast<int>(pids.size() * sizeof(pid_t)));
    if (pidCount <= 0) return result;

    result.reserve(static_cast<size_t>(pidCount));

    for (int i = 0; i < pidCount; ++i) {
        pid_t pid = pids[static_cast<size_t>(i)];
        if (pid <= 0) continue;

        // Get task info for CPU and memory usage.
        struct proc_taskinfo taskInfo{};
        int ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0,
                               &taskInfo, sizeof(taskInfo));
        if (ret <= 0) continue;

        // Get the process name via proc_pidpath.
        char pathBuf[PROC_PIDPATHINFO_MAXSIZE]{};
        int pathRet = proc_pidpath(pid, pathBuf, sizeof(pathBuf));

        ProcessResourceInfo info;
        info.pid           = static_cast<uint32_t>(pid);
        info.residentBytes = taskInfo.pti_resident_size;

        // CPU usage: total user+system time as a rough estimate.
        // pti_total_user + pti_total_system are in nanoseconds.
        // We compute a percentage based on elapsed wall time.
        // For a snapshot, we report RSS only; CPU% is sampled differentially
        // in the scan loop for accuracy. Here we use a rough heuristic.
        double totalCpuNs = static_cast<double>(taskInfo.pti_total_user +
                                                 taskInfo.pti_total_system);
        // Number of threads * potential = approximation for now.
        info.cpuPercent = 0.0; // Will be set to meaningful value below.

        // Use pti_threads_user + pti_threads_system for "current" CPU.
        // These measure recent CPU consumption in the kernel's scheduler.
        double recentNs = static_cast<double>(taskInfo.pti_threads_user +
                                               taskInfo.pti_threads_system);
        (void)totalCpuNs;

        // Rough percentage: (recent time / 1-second window) / cpuCount * 100.
        // This is an approximation; precise differential sampling would need
        // two snapshots. For anomaly detection, this is sufficient.
        if (recentNs > 0) {
            info.cpuPercent = (recentNs / 1e9) / static_cast<double>(cpuCount) * 100.0;
            if (info.cpuPercent > 100.0 * cpuCount) {
                info.cpuPercent = 100.0 * cpuCount;
            }
        }

        if (pathRet > 0) {
            std::string fullPath(pathBuf);
            auto pos = fullPath.find_last_of('/');
            info.name = (pos != std::string::npos)
                          ? fullPath.substr(pos + 1)
                          : fullPath;
        } else {
            info.name = "pid:" + std::to_string(pid);
        }

        result.push_back(std::move(info));
    }

#elif defined(_WIN32)
    // Windows implementation: EnumProcesses + GetProcessMemoryInfo.
    DWORD pids[4096]{};
    DWORD bytesReturned = 0;
    if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) return result;

    DWORD count = bytesReturned / sizeof(DWORD);
    result.reserve(count);

    for (DWORD i = 0; i < count; ++i) {
        if (pids[i] == 0) continue;

        HANDLE hProc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE, pids[i]);
        if (!hProc) continue;

        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);

        ProcessResourceInfo info;
        info.pid = pids[i];

        if (GetProcessMemoryInfo(hProc,
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            info.residentBytes = pmc.WorkingSetSize;
        }

        wchar_t exePath[MAX_PATH]{};
        DWORD pathLen = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, exePath, &pathLen)) {
            int needed = WideCharToMultiByte(
                CP_UTF8, 0, exePath, static_cast<int>(pathLen),
                nullptr, 0, nullptr, nullptr);
            if (needed > 0) {
                std::string path(static_cast<size_t>(needed), '\0');
                WideCharToMultiByte(CP_UTF8, 0, exePath,
                    static_cast<int>(pathLen), path.data(), needed,
                    nullptr, nullptr);
                auto pos = path.find_last_of("\\/");
                info.name = (pos != std::string::npos)
                              ? path.substr(pos + 1)
                              : path;
            }
        }

        CloseHandle(hProc);
        result.push_back(std::move(info));
    }
#endif

    return result;
}

} // namespace fikcer::ai

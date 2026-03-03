// ============================================================================
// FikcerAgent – AI Anomaly Detector Interface
// ============================================================================
// Heuristic + statistical anomaly detection engine.  Analyses rolling time-
// series data (CPU, RAM, per-process stats) to detect:
//
//   1. Sustained high-load spikes  (CPU/RAM above threshold for N samples)
//   2. Rapid usage ramps           (derivative exceeds threshold)
//   3. Per-process resource hogs   (single process consuming > X% CPU/RAM)
//   4. Memory leak patterns        (monotonic RAM growth over time)
//
// The engine is deliberately ML-free so it compiles anywhere with zero
// dependencies.  A virtual `Analyzer` base class is provided so that a
// future TensorFlow-Lite / ONNX / REST-API-based detector can be plugged
// in without touching any other module.
// ============================================================================
#pragma once

#include "core/monitor.h"

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace fikcer::ai {

// ── Anomaly types ──────────────────────────────────────────────────────────

enum class AnomalyType : uint8_t {
    NONE              = 0,
    CPU_SPIKE         = 1,   // Sustained high CPU
    CPU_RAMP          = 2,   // Rapidly increasing CPU
    MEMORY_SPIKE      = 3,   // Sustained high memory
    MEMORY_LEAK       = 4,   // Monotonically growing memory usage
    PROCESS_CPU_HOG   = 5,   // Single process hogging CPU
    PROCESS_MEM_HOG   = 6,   // Single process hogging memory
    SYSTEM_OVERLOAD   = 7,   // Both CPU and RAM critical simultaneously
    // ── System-level types (detected by deep scan + Gemini) ────────────
    DISK_SPACE_LOW    = 10,  // Disk partition running out of space
    DISK_HEALTH_WARN  = 11,  // Disk SMART warnings
    NETWORK_DOWN      = 12,  // Internet connectivity lost
    DNS_FAILURE       = 13,  // DNS resolution failing or slow
    MALWARE_DETECTED  = 14,  // Suspicious / malicious process found
    HIGH_TEMPERATURE  = 15,  // CPU overheating
    BATTERY_CRITICAL  = 16,  // Battery dangerously low
    FIREWALL_DISABLED = 17,  // System firewall is off
    DRIVER_ISSUE      = 18,  // Driver problem (Windows)
    INTEGRITY_ERROR   = 19,  // System file integrity issue
};

enum class Severity : uint8_t {
    LOW      = 0,
    MEDIUM   = 1,
    HIGH     = 2,
    CRITICAL = 3,
};

/// Human-readable tag for severity.
[[nodiscard]] constexpr std::string_view severityTag(Severity s) noexcept {
    switch (s) {
        case Severity::LOW:      return "LOW";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::HIGH:     return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

[[nodiscard]] constexpr std::string_view anomalyTag(AnomalyType t) noexcept {
    switch (t) {
        case AnomalyType::NONE:              return "NONE";
        case AnomalyType::CPU_SPIKE:         return "CPU_SPIKE";
        case AnomalyType::CPU_RAMP:          return "CPU_RAMP";
        case AnomalyType::MEMORY_SPIKE:      return "MEMORY_SPIKE";
        case AnomalyType::MEMORY_LEAK:       return "MEMORY_LEAK";
        case AnomalyType::PROCESS_CPU_HOG:   return "PROC_CPU_HOG";
        case AnomalyType::PROCESS_MEM_HOG:   return "PROC_MEM_HOG";
        case AnomalyType::SYSTEM_OVERLOAD:   return "SYS_OVERLOAD";
        case AnomalyType::DISK_SPACE_LOW:    return "DISK_LOW";
        case AnomalyType::DISK_HEALTH_WARN:  return "DISK_HEALTH";
        case AnomalyType::NETWORK_DOWN:      return "NET_DOWN";
        case AnomalyType::DNS_FAILURE:       return "DNS_FAIL";
        case AnomalyType::MALWARE_DETECTED:  return "MALWARE";
        case AnomalyType::HIGH_TEMPERATURE:  return "HIGH_TEMP";
        case AnomalyType::BATTERY_CRITICAL:  return "BATT_CRIT";
        case AnomalyType::FIREWALL_DISABLED: return "FW_OFF";
        case AnomalyType::DRIVER_ISSUE:      return "DRIVER";
        case AnomalyType::INTEGRITY_ERROR:   return "INTEGRITY";
    }
    return "UNKNOWN";
}

// ── Per-process resource snapshot ──────────────────────────────────────────

struct ProcessResourceInfo {
    uint32_t    pid          = 0;
    std::string name;
    double      cpuPercent   = 0.0;   ///< % of total CPU this process uses.
    uint64_t    residentBytes= 0;     ///< Resident memory (RSS) in bytes.
};

// ── Anomaly record ─────────────────────────────────────────────────────────

struct Anomaly {
    AnomalyType type     = AnomalyType::NONE;
    Severity    severity = Severity::LOW;
    std::string description;            ///< Human-readable explanation.
    std::string recommendation;         ///< Suggested auto-fix or user action.
    uint32_t    relatedPid = 0;         ///< 0 if system-wide anomaly.
    std::string relatedProcess;         ///< Process name, if applicable.
    double      metricValue = 0.0;      ///< The value that triggered detection.
    std::chrono::steady_clock::time_point timestamp;
};

/// Callback invoked when anomalies are detected.
using AnomalyCallback = std::function<void(const std::vector<Anomaly>&)>;

// ── Abstract analyzer interface (for future ML plug-in) ────────────────────

class Analyzer {
public:
    virtual ~Analyzer() = default;

    /// Feed a system snapshot; return any anomalies detected.
    [[nodiscard]] virtual std::vector<Anomaly> analyse(
        const core::SystemStats& stats,
        const std::vector<ProcessResourceInfo>& processes) = 0;
};

// ── Built-in heuristic analyzer ────────────────────────────────────────────

class HeuristicAnalyzer final : public Analyzer {
public:
    HeuristicAnalyzer();
    ~HeuristicAnalyzer() override = default;

    [[nodiscard]] std::vector<Anomaly> analyse(
        const core::SystemStats& stats,
        const std::vector<ProcessResourceInfo>& processes) override;

    // ── Tuning ─────────────────────────────────────────────────────────────
    void setCpuSpikeThreshold(double percent, unsigned int consecutiveSamples);
    void setMemorySpikeThreshold(double percent, unsigned int consecutiveSamples);
    void setCpuRampThreshold(double deltaPerSample);
    void setMemoryLeakWindowSize(unsigned int samples);
    void setProcessCpuHogThreshold(double percent);
    void setProcessMemHogBytes(uint64_t bytes);

private:
    // ── Detection helpers ──────────────────────────────────────────────────
    void detectCpuSpike(const core::SystemStats& stats, std::vector<Anomaly>& out);
    void detectCpuRamp(const core::SystemStats& stats, std::vector<Anomaly>& out);
    void detectMemorySpike(const core::SystemStats& stats, std::vector<Anomaly>& out);
    void detectMemoryLeak(const core::SystemStats& stats, std::vector<Anomaly>& out);
    void detectProcessHogs(const std::vector<ProcessResourceInfo>& procs,
                           std::vector<Anomaly>& out);
    void detectSystemOverload(const core::SystemStats& stats, std::vector<Anomaly>& out);

    [[nodiscard]] Severity computeSeverity(double value, double threshold) const;

    // ── Rolling history ────────────────────────────────────────────────────
    struct Sample {
        double cpu  = 0.0;
        double mem  = 0.0;
        uint64_t memAvail = 0;
        std::chrono::steady_clock::time_point time;
    };

    std::deque<Sample> history_;
    static constexpr std::size_t MAX_HISTORY = 120;  // 10 min at 5s interval

    // ── Thresholds ─────────────────────────────────────────────────────────
    double       cpuSpikeThreshold_       = 90.0;
    unsigned int cpuSpikeConsecutive_      = 3;
    unsigned int cpuSpikeCounter_          = 0;

    double       memSpikeThreshold_       = 90.0;
    unsigned int memSpikeConsecutive_      = 3;
    unsigned int memSpikeCounter_          = 0;

    double       cpuRampDelta_            = 15.0;   // % per sample

    unsigned int memLeakWindow_           = 12;     // ~1 min at 5s
    double       processCpuHogThreshold_  = 80.0;   // Single process %
    uint64_t     processMemHogBytes_      = 2ULL * 1024 * 1024 * 1024; // 2 GB
};

// ── Anomaly Detector (orchestrator) ────────────────────────────────────────

class AnomalyDetector final {
public:
    AnomalyDetector();
    ~AnomalyDetector() = default;

    AnomalyDetector(const AnomalyDetector&) = delete;
    AnomalyDetector& operator=(const AnomalyDetector&) = delete;

    /// Replace the default heuristic analyzer with a custom one.
    void setAnalyzer(std::unique_ptr<Analyzer> analyzer);

    /// Register a callback for anomaly events.
    void setCallback(AnomalyCallback cb);

    /// Feed a new system snapshot + per-process data.
    /// Returns detected anomalies (also fires the callback).
    std::vector<Anomaly> feed(
        const core::SystemStats& stats,
        const std::vector<ProcessResourceInfo>& processes);

    /// Get the per-process resource info for the current system.
    /// Platform-specific implementation.
    [[nodiscard]] static std::vector<ProcessResourceInfo> sampleProcessResources();

private:
    std::unique_ptr<Analyzer> analyzer_;
    AnomalyCallback           callback_;
    mutable std::mutex         mutex_;
};

} // namespace fikcer::ai

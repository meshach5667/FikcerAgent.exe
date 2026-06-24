// ============================================================================
// FikcerAgent – World State Model
// ============================================================================
// A unified, point-in-time snapshot of the entire system.  All monitoring
// data is consolidated into a single coherent model that the AI planner
// can reason over.
//
// The WorldState can be serialized to JSON for inclusion in Gemini prompts.
// ============================================================================
#pragma once

#include "core/monitor.h"
#include "core/system_scanner.h"
#include "ai/anomaly_detector.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace fikcer::agent {

// Threat information 
struct ThreatInfo {
    std::string name;           ///< Process or file name.
    std::string type;           ///< "malware", "miner", "suspicious", etc.
    uint32_t    pid = 0;        ///< Associated PID, if applicable.
    std::string path;           ///< File path, if applicable.
    std::string reason;         ///< Why it's considered a threat.
    std::string severity;       ///< "low", "medium", "high", "critical"
};

// ── Service status

struct ServiceInfo {
    std::string name;
    std::string status;         ///< "running", "stopped", "unknown"
};

// ── World State 

struct WorldState {
    // ── Health 
    double healthScore    = 100.0;  ///< Composite health score (0-100).
    double cpuPercent     = 0.0;    ///< Current CPU usage %.
    double memPercent     = 0.0;    ///< Current memory usage %.
    double maxDiskPercent = 0.0;    ///< Highest disk usage % across partitions.
    uint64_t memTotalBytes     = 0;
    uint64_t memAvailableBytes = 0;

    // ── Security ───────────────────────────────────────────────────────────
    bool firewallEnabled  = false;
    bool defenderActive   = true;   ///< Antivirus / XProtect active.
    std::vector<ThreatInfo> activeThreats;

    // ── Network ────────────────────────────────────────────────────────────
    bool        internetReachable = false;
    bool        dnsWorking        = false;
    double      dnsLatencyMs      = -1.0;
    double      pingLatencyMs     = -1.0;
    std::string gateway;
    std::string activeInterface;

    // ── Services ───────────────────────────────────────────────────────────
    std::vector<ServiceInfo> criticalServices;

    // ── Hardware ───────────────────────────────────────────────────────────
    double cpuTemperature     = -1.0;
    bool   hasBattery         = false;
    double batteryPercent     = 0.0;
    bool   batteryCharging    = false;

    // ── Disk ───────────────────────────────────────────────────────────────
    std::vector<core::DiskInfo> disks;

    // ── Anomalies (from heuristic detector) ────────────────────────────────
    std::vector<ai::Anomaly> activeAnomalies;

    // ── Top processes ──────────────────────────────────────────────────────
    std::vector<ai::ProcessResourceInfo> topProcesses;

    // ── Meta ───────────────────────────────────────────────────────────────
    std::string osVersion;
    double      uptimeHours = 0.0;
    std::string timestamp;

    // ── Methods ────────────────────────────────────────────────────────────

    /// Build the world state from current monitoring subsystems.
    void update(const core::SystemStats& stats,
                const core::SystemDiagnostics& diag,
                const std::vector<ai::Anomaly>& anomalies,
                const std::vector<ai::ProcessResourceInfo>& processes,
                double computedHealthScore);

    /// Serialize to a JSON string for Gemini prompts.
    [[nodiscard]] std::string toJson() const;

    /// Serialize to a human-readable summary.
    [[nodiscard]] std::string toSummary() const;
};

} // namespace fikcer::agent

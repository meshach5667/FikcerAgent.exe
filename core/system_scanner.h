// ============================================================================
// FikcerAgent – Deep System Scanner Interface
// ============================================================================
// Collects comprehensive system diagnostics beyond basic CPU/RAM:
//
//   • Disk space & health
//   • Network connectivity & DNS
//   • Suspicious / malware process detection
//   • CPU temperature
//   • Battery health
//   • System log errors
//   • System uptime
//
// All results are packaged into a SystemDiagnostics struct and can also be
// serialised into a plain-text report for Gemini AI analysis.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fikcer::core {

// ── Diagnostic sub-structures ──────────────────────────────────────────────

struct DiskInfo {
    std::string mountPoint;
    std::string filesystem;
    uint64_t    totalBytes     = 0;
    uint64_t    freeBytes      = 0;
    double      usagePercent   = 0.0;
};

struct NetworkStatus {
    bool        internetReachable = false;
    bool        dnsWorking        = false;
    double      dnsLatencyMs      = -1.0;
    double      pingLatencyMs     = -1.0;
    std::string gateway;
    std::string activeInterface;
};

struct SuspiciousProcess {
    uint32_t    pid  = 0;
    std::string name;
    std::string path;
    std::string reason;   ///< Why it's flagged as suspicious.
};

struct BatteryInfo {
    bool   hasBattery   = false;
    double chargePercent = -1.0;
    bool   isCharging    = false;
    std::string condition;  ///< "Normal", "Service Recommended", etc.
};

// ── Composite diagnostics ──────────────────────────────────────────────────

struct SystemDiagnostics {
    // Disk
    std::vector<DiskInfo>   disks;

    // Network
    NetworkStatus           network;

    // Security
    std::vector<SuspiciousProcess> suspiciousProcesses;

    // Hardware
    double                  cpuTemperature = -1.0;  // °C, -1 = unavailable
    BatteryInfo             battery;

    // System
    double                  uptimeHours = 0.0;
    std::string             osVersion;
    bool                    firewallEnabled = false;

    // Recent error log entries
    std::vector<std::string> recentErrors;

    // Timestamp
    std::string              scanTimestamp;
};

// ── System Scanner ─────────────────────────────────────────────────────────

class SystemScanner final {
public:
    SystemScanner() = default;

    /// Perform a full system diagnostic scan.
    [[nodiscard]] SystemDiagnostics scan();

    /// Generate a human-readable text report from diagnostics.
    /// Suitable for sending to Gemini for AI analysis.
    [[nodiscard]] static std::string generateReport(
        const SystemDiagnostics& diag,
        double cpuPercent, double memPercent,
        uint64_t memTotal, uint64_t memAvail);

private:
    // ── Individual scanners 
    void scanDisks(SystemDiagnostics& d);
    void scanNetwork(SystemDiagnostics& d);
    void scanSuspiciousProcesses(SystemDiagnostics& d);
    void scanTemperature(SystemDiagnostics& d);
    void scanBattery(SystemDiagnostics& d);
    void scanUptime(SystemDiagnostics& d);
    void scanOsVersion(SystemDiagnostics& d);
    void scanFirewall(SystemDiagnostics& d);
    void scanRecentErrors(SystemDiagnostics& d);

    // ── Suspicious process helpers ─────────────────────────────────────────
    [[nodiscard]] static bool isKnownMalwareName(const std::string& name);
    [[nodiscard]] static bool isSuspiciousPath(const std::string& path);
};

} // namespace fikcer::core

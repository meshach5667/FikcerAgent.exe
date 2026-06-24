// ============================================================================
// FikcerAgent – World State Model Implementation
// ============================================================================
#include "agent/world_state.h"
#include "utils/logger.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace fikcer::agent {

void WorldState::update(const core::SystemStats& stats,
                        const core::SystemDiagnostics& diag,
                        const std::vector<ai::Anomaly>& anomalies,
                        const std::vector<ai::ProcessResourceInfo>& processes,
                        double computedHealthScore)
{
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    timestamp = ts.str();

    healthScore       = computedHealthScore;
    cpuPercent        = stats.cpuUsagePercent;
    memPercent        = stats.memUsagePercent;
    memTotalBytes     = stats.memTotalBytes;
    memAvailableBytes = stats.memAvailableBytes;

    disks = diag.disks;
    maxDiskPercent = 0.0;
    for (const auto& d : disks)
        if (d.usagePercent > maxDiskPercent)
            maxDiskPercent = d.usagePercent;

    firewallEnabled = diag.firewallEnabled;
    defenderActive  = true;

    activeThreats.clear();
    for (const auto& sp : diag.suspiciousProcesses) {
        ThreatInfo ti;
        ti.name = sp.name; ti.pid = sp.pid; ti.path = sp.path;
        ti.reason = sp.reason; ti.type = "suspicious"; ti.severity = "medium";
        activeThreats.push_back(std::move(ti));
    }

    internetReachable = diag.network.internetReachable;
    dnsWorking        = diag.network.dnsWorking;
    dnsLatencyMs      = diag.network.dnsLatencyMs;
    pingLatencyMs     = diag.network.pingLatencyMs;
    gateway           = diag.network.gateway;
    activeInterface   = diag.network.activeInterface;
    cpuTemperature    = diag.cpuTemperature;
    hasBattery        = diag.battery.hasBattery;
    batteryPercent    = diag.battery.chargePercent;
    batteryCharging   = diag.battery.isCharging;
    osVersion         = diag.osVersion;
    uptimeHours       = diag.uptimeHours;
    activeAnomalies   = anomalies;

    topProcesses = processes;
    std::sort(topProcesses.begin(), topProcesses.end(),
              [](const auto& a, const auto& b) {
                  return a.cpuPercent > b.cpuPercent;
              });
    if (topProcesses.size() > 10) topProcesses.resize(10);
}

static std::string jsonEsc(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\t': r += "\\t";  break;
            default:   r += c;
        }
    }
    return r;
}

std::string WorldState::toJson() const {
    std::ostringstream j;
    j << std::fixed << std::setprecision(1);
    j << "{";
    j << "\"health_score\":" << healthScore;
    j << ",\"cpu\":" << cpuPercent;
    j << ",\"ram\":" << memPercent;
    j << ",\"disk\":" << maxDiskPercent;
    j << ",\"firewall\":" << (firewallEnabled ? "true" : "false");
    j << ",\"defender\":" << (defenderActive ? "true" : "false");
    j << ",\"internet\":" << (internetReachable ? "true" : "false");
    j << ",\"dns\":\"" << (dnsWorking ? "ok" : "failed") << "\"";
    if (dnsLatencyMs >= 0) j << ",\"dns_latency_ms\":" << dnsLatencyMs;
    if (cpuTemperature >= 0) j << ",\"cpu_temp_c\":" << cpuTemperature;
    if (hasBattery) {
        j << ",\"battery\":" << batteryPercent;
        j << ",\"charging\":" << (batteryCharging ? "true" : "false");
    }
    j << ",\"threats\":" << activeThreats.size();
    j << ",\"anomalies\":" << activeAnomalies.size();
    j << ",\"os\":\"" << jsonEsc(osVersion) << "\"";
    j << ",\"uptime_h\":" << uptimeHours;

    j << ",\"top_processes\":[";
    for (size_t i = 0; i < topProcesses.size(); ++i) {
        if (i) j << ",";
        j << "{\"name\":\"" << jsonEsc(topProcesses[i].name) << "\""
          << ",\"pid\":" << topProcesses[i].pid
          << ",\"cpu\":" << topProcesses[i].cpuPercent << "}";
    }
    j << "]";

    j << ",\"disks\":[";
    for (size_t i = 0; i < disks.size(); ++i) {
        if (i) j << ",";
        j << "{\"mount\":\"" << jsonEsc(disks[i].mountPoint) << "\""
          << ",\"used\":" << disks[i].usagePercent << "}";
    }
    j << "]";

    j << "}";
    return j.str();
}

std::string WorldState::toSummary() const {
    std::ostringstream s;
    s << std::fixed << std::setprecision(1);
    s << "=== SYSTEM STATE ===\n";
    s << "Health: " << healthScore << "/100  Time: " << timestamp << "\n";
    s << "CPU: " << cpuPercent << "%  RAM: " << memPercent << "%\n";
    s << "Firewall: " << (firewallEnabled ? "ON" : "OFF")
      << "  Internet: " << (internetReachable ? "OK" : "DOWN")
      << "  DNS: " << (dnsWorking ? "OK" : "FAIL") << "\n";
    if (!activeThreats.empty())
        s << "!! " << activeThreats.size() << " active threat(s)\n";
    if (!activeAnomalies.empty())
        s << activeAnomalies.size() << " anomalie(s) detected\n";
    return s.str();
}

} // namespace fikcer::agent

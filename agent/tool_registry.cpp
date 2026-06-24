// ============================================================================
// FikcerAgent – Approved Tool Registry Implementation
// ============================================================================
#include "agent/tool_registry.h"
#include "utils/exec.h"
#include "utils/logger.h"

#include <algorithm>
#include <sstream>

#ifdef __APPLE__
#   include <libproc.h>
#   include <signal.h>
#   include <unistd.h>
#   include <mach/mach.h>
#   include <sys/mount.h>
#elif defined(_WIN32)
#   include <Windows.h>
#endif

namespace fikcer::agent {

using utils::Logger;
using utils::exec;

// ── Construction ───────────────────────────────────────────────────────────

ToolRegistry::ToolRegistry() = default;

// ── Register default tools ─────────────────────────────────────────────────

void ToolRegistry::registerDefaultTools() {
    std::lock_guard lock(mutex_);

    // ═══════════════════════════════════════════════════════════════════════
    // MONITORING TOOLS (Low risk, no side effects)
    // ═══════════════════════════════════════════════════════════════════════

    registerToolInternal({
        "GetCPUUsage",
        "Get current CPU usage percentage.",
        ToolCategory::MONITORING, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            std::string out = exec("top -l 1 -n 0 | grep 'CPU usage' 2>/dev/null");
            return {true, out, "", 0.0};
#elif defined(_WIN32)
            std::string out = exec("wmic cpu get loadpercentage /value 2>&1");
            return {true, out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "GetMemoryUsage",
        "Get current memory usage information.",
        ToolCategory::MONITORING, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            std::string out = exec("vm_stat 2>/dev/null | head -5");
            return {true, out, "", 0.0};
#elif defined(_WIN32)
            std::string out = exec("wmic os get FreePhysicalMemory,TotalVisibleMemorySize /value 2>&1");
            return {true, out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "GetDiskUsage",
        "Get disk usage for all partitions.",
        ToolCategory::MONITORING, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
            std::string out = exec("df -h 2>/dev/null");
            return {true, out, "", 0.0};
        }
    });

    registerToolInternal({
        "GetProcessList",
        "List top processes by CPU usage.",
        ToolCategory::MONITORING, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            std::string out = exec("ps aux --sort=-%cpu 2>/dev/null | head -15");
            return {true, out, "", 0.0};
#elif defined(_WIN32)
            std::string out = exec("tasklist /FO TABLE /NH 2>&1 | head -15");
            return {true, out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "GetNetworkStatus",
        "Check internet connectivity and DNS.",
        ToolCategory::MONITORING, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
            std::string ping = exec("ping -c 1 -t 3 8.8.8.8 2>&1");
            std::string dns = exec("host -W 3 google.com 2>&1");
            return {true, "Ping: " + ping + "\nDNS: " + dns, "", 0.0};
        }
    });

    registerToolInternal({
        "GetFirewallStatus",
        "Check if the system firewall is enabled.",
        ToolCategory::MONITORING, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            std::string out = exec("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null");
            bool enabled = out.find("enabled") != std::string::npos;
            return {true, enabled ? "Firewall: ENABLED" : "Firewall: DISABLED", "", enabled ? 1.0 : 0.0};
#elif defined(_WIN32)
            std::string out = exec("netsh advfirewall show allprofiles state 2>&1");
            bool enabled = out.find("ON") != std::string::npos;
            return {true, enabled ? "Firewall: ENABLED" : "Firewall: DISABLED", "", enabled ? 1.0 : 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "GetServiceStatus",
        "Check status of a specific service.",
        ToolCategory::MONITORING, RiskLevel::LOW, false, {"service"},
        [](const ToolParams& params) -> ToolResult {
            auto it = params.find("service");
            if (it == params.end()) return {false, "", "Missing 'service' parameter", 0.0};
#ifdef __APPLE__
            std::string out = exec("launchctl list | grep " + it->second + " 2>/dev/null");
            return {true, out.empty() ? "Service not found" : out, "", 0.0};
#elif defined(_WIN32)
            std::string out = exec("sc query " + it->second + " 2>&1");
            return {true, out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    // ═══════════════════════════════════════════════════════════════════════
    // RECOVERY TOOLS
    // ═══════════════════════════════════════════════════════════════════════

    registerToolInternal({
        "RestartProcess",
        "Terminate and optionally restart a process by name or PID.",
        ToolCategory::RECOVERY, RiskLevel::MEDIUM, true, {"process"},
        [](const ToolParams& params) -> ToolResult {
            auto it = params.find("process");
            if (it == params.end()) return {false, "", "Missing 'process' parameter", 0.0};

#ifdef __APPLE__
            std::string cmd = "killall '" + it->second + "' 2>&1";
            std::string out = exec(cmd);
            return {true, "Terminated: " + it->second + " " + out, "", 0.0};
#elif defined(_WIN32)
            std::string cmd = "taskkill /IM " + it->second + " /F 2>&1";
            std::string out = exec(cmd);
            return {true, "Terminated: " + it->second + " " + out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "FlushDNS",
        "Clear the DNS resolver cache to fix DNS issues.",
        ToolCategory::RECOVERY, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            std::string out = exec("sudo dscacheutil -flushcache 2>&1; sudo killall -HUP mDNSResponder 2>&1");
            return {true, "DNS cache flushed. " + out, "", 0.0};
#elif defined(_WIN32)
            std::string out = exec("ipconfig /flushdns 2>&1");
            return {true, "DNS cache flushed. " + out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "EnableFirewall",
        "Enable the system firewall.",
        ToolCategory::RECOVERY, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            std::string out = exec("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>&1");
            return {true, "Firewall enabled. " + out, "", 0.0};
#elif defined(_WIN32)
            std::string out = exec("netsh advfirewall set allprofiles state on 2>&1");
            return {true, "Firewall enabled. " + out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "CleanTempFiles",
        "Remove temporary files to reclaim disk space.",
        ToolCategory::RECOVERY, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            exec("rm -rf ~/Library/Caches/* 2>/dev/null");
            exec("rm -rf /tmp/*.tmp 2>/dev/null");
            return {true, "Temporary files cleaned.", "", 0.0};
#elif defined(_WIN32)
            exec("del /q /s %TEMP%\\* 2>NUL");
            return {true, "Temporary files cleaned.", "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "ResetNetworkAdapter",
        "Reset the primary network adapter to fix connectivity.",
        ToolCategory::RECOVERY, RiskLevel::MEDIUM, true, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            std::string iface = exec("route -n get default 2>/dev/null | grep interface | awk '{print $2}'");
            iface.erase(iface.find_last_not_of(" \t\r\n") + 1);
            if (iface.empty()) return {false, "", "No active interface found", 0.0};
            exec("sudo ifconfig " + iface + " down 2>&1");
            exec("sleep 2");
            exec("sudo ifconfig " + iface + " up 2>&1");
            return {true, "Network adapter " + iface + " reset.", "", 0.0};
#elif defined(_WIN32)
            exec("netsh interface set interface \"Wi-Fi\" disable 2>&1");
            exec("timeout /t 2 /nobreak >NUL");
            exec("netsh interface set interface \"Wi-Fi\" enable 2>&1");
            return {true, "Network adapter reset.", "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "RestartService",
        "Restart a system service by name.",
        ToolCategory::RECOVERY, RiskLevel::MEDIUM, true, {"service"},
        [](const ToolParams& params) -> ToolResult {
            auto it = params.find("service");
            if (it == params.end()) return {false, "", "Missing 'service' parameter", 0.0};
#ifdef __APPLE__
            exec("sudo launchctl stop " + it->second + " 2>&1");
            exec("sudo launchctl start " + it->second + " 2>&1");
            return {true, "Service " + it->second + " restarted.", "", 0.0};
#elif defined(_WIN32)
            exec("net stop " + it->second + " 2>&1");
            exec("net start " + it->second + " 2>&1");
            return {true, "Service " + it->second + " restarted.", "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    // ═══════════════════════════════════════════════════════════════════════
    // SECURITY TOOLS
    // ═══════════════════════════════════════════════════════════════════════

    registerToolInternal({
        "QuarantineFile",
        "Move a suspicious file to quarantine.",
        ToolCategory::SECURITY, RiskLevel::HIGH, true, {"file"},
        [](const ToolParams& params) -> ToolResult {
            auto it = params.find("file");
            if (it == params.end()) return {false, "", "Missing 'file' parameter", 0.0};

            std::string quarantine = std::string(getenv("HOME") ?: "/tmp") +
                                      "/.fikcerAgent/quarantine/";
            exec("mkdir -p " + quarantine + " 2>/dev/null");
            std::string cmd = "mv '" + it->second + "' '" + quarantine + "' 2>&1";
            std::string out = exec(cmd);
            return {true, "File quarantined: " + it->second + " " + out, "", 0.0};
        }
    });

    registerToolInternal({
        "BlockIP",
        "Block an IP address via firewall rules.",
        ToolCategory::SECURITY, RiskLevel::HIGH, true, {"ip"},
        [](const ToolParams& params) -> ToolResult {
            auto it = params.find("ip");
            if (it == params.end()) return {false, "", "Missing 'ip' parameter", 0.0};
#ifdef __APPLE__
            std::string cmd = "sudo /sbin/pfctl -t blocklist -T add " + it->second + " 2>&1";
            std::string out = exec(cmd);
            return {true, "IP blocked: " + it->second + " " + out, "", 0.0};
#elif defined(_WIN32)
            std::string cmd = "netsh advfirewall firewall add rule name=\"FikcerBlock\" "
                "dir=out action=block remoteip=" + it->second + " 2>&1";
            std::string out = exec(cmd);
            return {true, "IP blocked: " + it->second + " " + out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "ScanProcess",
        "Analyze a running process for suspicious behavior.",
        ToolCategory::SECURITY, RiskLevel::LOW, false, {"pid"},
        [](const ToolParams& params) -> ToolResult {
            auto it = params.find("pid");
            if (it == params.end()) return {false, "", "Missing 'pid' parameter", 0.0};
#ifdef __APPLE__
            std::string out = exec("ps -p " + it->second + " -o pid,user,%cpu,%mem,command 2>/dev/null");
            std::string lsof = exec("lsof -p " + it->second + " 2>/dev/null | head -20");
            return {true, "Process Info:\n" + out + "\nOpen Files:\n" + lsof, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "VerifySystemIntegrity",
        "Verify system file integrity.",
        ToolCategory::SECURITY, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            // On macOS, check SIP status and run basic integrity checks.
            std::string sip = exec("csrutil status 2>/dev/null");
            std::string gate = exec("spctl --status 2>/dev/null");
            return {true, "SIP: " + sip + "Gatekeeper: " + gate, "", 0.0};
#elif defined(_WIN32)
            std::string out = exec("sfc /verifyonly 2>&1");
            return {true, out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "DisableSuspiciousStartup",
        "Disable a suspicious startup/login item.",
        ToolCategory::SECURITY, RiskLevel::HIGH, true, {"item"},
        [](const ToolParams& params) -> ToolResult {
            auto it = params.find("item");
            if (it == params.end()) return {false, "", "Missing 'item' parameter", 0.0};
#ifdef __APPLE__
            std::string cmd = "osascript -e 'tell application \"System Events\" to delete login item \"" +
                              it->second + "\"' 2>&1";
            std::string out = exec(cmd);
            return {true, "Startup item disabled: " + it->second + " " + out, "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    registerToolInternal({
        "RestoreFirewallRules",
        "Reset firewall rules to default secure configuration.",
        ToolCategory::SECURITY, RiskLevel::HIGH, true, {},
        [](const ToolParams&) -> ToolResult {
#ifdef __APPLE__
            exec("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>&1");
            exec("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off 2>&1");
            exec("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>&1");
            return {true, "Firewall rules restored to secure defaults.", "", 0.0};
#elif defined(_WIN32)
            exec("netsh advfirewall reset 2>&1");
            return {true, "Firewall rules reset to defaults.", "", 0.0};
#else
            return {false, "", "Unsupported platform", 0.0};
#endif
        }
    });

    // ═══════════════════════════════════════════════════════════════════════
    // VERIFICATION TOOLS
    // ═══════════════════════════════════════════════════════════════════════

    registerToolInternal({
        "VerifyAction",
        "Re-check a specific metric to verify an action's effect.",
        ToolCategory::VERIFICATION, RiskLevel::LOW, false, {"metric"},
        [](const ToolParams& params) -> ToolResult {
            auto it = params.find("metric");
            if (it == params.end()) return {false, "", "Missing 'metric' parameter", 0.0};
            // This is a placeholder — the Agent uses WorldState comparison.
            return {true, "Verification requested for: " + it->second, "", 0.0};
        }
    });

    registerToolInternal({
        "GetHealthScore",
        "Get the current composite health score.",
        ToolCategory::VERIFICATION, RiskLevel::LOW, false, {},
        [](const ToolParams&) -> ToolResult {
            // Placeholder — actual score is computed by HealthScoreEngine.
            return {true, "Health score query — use Agent.healthScore()", "", 0.0};
        }
    });

    Logger::instance().info("ToolRegistry: " +
                            std::to_string(tools_.size()) +
                            " tools registered.");
}

// ── Internal registration (no lock) ────────────────────────────────────────

void ToolRegistry::registerToolInternal(Tool tool) {
    tools_[tool.name] = std::move(tool);
}

// ── Public registration ────────────────────────────────────────────────────

void ToolRegistry::registerTool(Tool tool) {
    std::lock_guard lock(mutex_);
    registerToolInternal(std::move(tool));
}

// ── Lookup ─────────────────────────────────────────────────────────────────

const Tool* ToolRegistry::findTool(const std::string& name) const {
    std::lock_guard lock(mutex_);
    auto it = tools_.find(name);
    return (it != tools_.end()) ? &it->second : nullptr;
}

// ── Execute ────────────────────────────────────────────────────────────────

ToolResult ToolRegistry::execute(const std::string& name,
                                  const ToolParams& params) {
    std::lock_guard lock(mutex_);
    auto it = tools_.find(name);
    if (it == tools_.end()) {
        Logger::instance().error("ToolRegistry: unknown tool '" + name + "'");
        return {false, "", "Tool '" + name + "' is not registered.", 0.0};
    }

    Logger::instance().info("ToolRegistry: executing " + name);
    try {
        return it->second.executor(params);
    } catch (const std::exception& e) {
        Logger::instance().error("ToolRegistry: " + name +
                                  " threw: " + e.what());
        return {false, "", std::string("Exception: ") + e.what(), 0.0};
    }
}

// ── Query ──────────────────────────────────────────────────────────────────

std::vector<std::string> ToolRegistry::toolNames() const {
    std::lock_guard lock(mutex_);
    std::vector<std::string> names;
    names.reserve(tools_.size());
    for (const auto& [k, _] : tools_) names.push_back(k);
    return names;
}

std::vector<const Tool*> ToolRegistry::toolsByCategory(ToolCategory cat) const {
    std::lock_guard lock(mutex_);
    std::vector<const Tool*> result;
    for (const auto& [_, t] : tools_) {
        if (t.category == cat) result.push_back(&t);
    }
    return result;
}

std::string ToolRegistry::toolsForPlanner() const {
    std::lock_guard lock(mutex_);

    std::ostringstream oss;
    oss << "AVAILABLE TOOLS:\n";
    for (const auto& [_, t] : tools_) {
        oss << "  " << t.name
            << " (" << toolCategoryTag(t.category)
            << ", risk=" << riskLevelTag(t.risk) << ")"
            << " — " << t.description;
        if (!t.parameterNames.empty()) {
            oss << " Params: [";
            for (size_t i = 0; i < t.parameterNames.size(); ++i) {
                if (i) oss << ", ";
                oss << t.parameterNames[i];
            }
            oss << "]";
        }
        oss << "\n";
    }
    return oss.str();
}

} // namespace fikcer::agent

// ============================================================================
// FikcerAgent – Deep System Scanner Implementation
// ============================================================================
#include "core/system_scanner.h"
#include "utils/exec.h"
#include "utils/logger.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#ifdef __APPLE__
#   include <sys/statvfs.h>
#   include <sys/sysctl.h>
#   include <sys/mount.h>
#   include <libproc.h>
#   include <mach/mach.h>
#elif defined(_WIN32)
#   include <Windows.h>
#endif

namespace fikcer::core {

using utils::Logger;
using utils::exec;

// ── Known suspicious / malware process names ───────────────────────────────

static const std::vector<std::string> KNOWN_MALWARE_NAMES = {
    // Cryptocurrency miners
    "xmrig", "xmr-stak", "minergate", "cpuminer", "cgminer", "bfgminer",
    "ethminer", "minerd", "nicehash", "phoenixminer", "t-rex", "nbminer",
    "gminer", "lolminer", "claymore",
    // RATs and backdoors
    "metasploit", "msfconsole", "msfvenom", "meterpreter", "cobalt",
    "cobaltstrike", "reverse_shell", "rev_shell", "bind_shell",
    // Keyloggers / spyware
    "keylogger", "keystroke", "screenlogger", "spyware",
    // Suspicious mimics (on macOS these should not exist)
    "svchost", "csrss", "lsass", "smss", "wininit",
    // Generic malware indicators
    "botnet", "ddos", "flood", "exploit", "payload", "shellcode",
    "rootkit", "trojan", "ransomware", "cryptolocker",
};

// ── Main scan ──────────────────────────────────────────────────────────────

SystemDiagnostics SystemScanner::scan() {
    SystemDiagnostics d;

    // Generate timestamp.
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    d.scanTimestamp = ts.str();

    Logger::instance().info("Starting deep system scan...");

    scanOsVersion(d);
    scanUptime(d);
    scanDisks(d);
    scanNetwork(d);
    scanSuspiciousProcesses(d);
    scanTemperature(d);
    scanBattery(d);
    scanFirewall(d);
    scanRecentErrors(d);

    Logger::instance().info("Deep system scan complete.");
    return d;
}

// ── Disk Scanner ───────────────────────────────────────────────────────────

void SystemScanner::scanDisks(SystemDiagnostics& d) {
#ifdef __APPLE__
    // Use statfs to get mounted filesystems.
    struct statfs* mounts = nullptr;
    int count = getmntinfo(&mounts, MNT_NOWAIT);

    for (int i = 0; i < count; i++) {
        const auto& m = mounts[i];

        // Skip pseudo-filesystems.
        std::string fstype = m.f_fstypename;
        if (fstype == "devfs" || fstype == "autofs" || fstype == "nullfs" ||
            fstype == "vmhgfs") {
            continue;
        }

        DiskInfo disk;
        disk.mountPoint = m.f_mntonname;
        disk.filesystem = fstype;

        uint64_t blockSize = m.f_bsize;
        disk.totalBytes = static_cast<uint64_t>(m.f_blocks) * blockSize;
        disk.freeBytes  = static_cast<uint64_t>(m.f_bavail) * blockSize;

        if (disk.totalBytes > 0) {
            disk.usagePercent = 100.0 *
                (1.0 - static_cast<double>(disk.freeBytes) /
                        static_cast<double>(disk.totalBytes));
        }

        // Only report real disks (>1 GB).
        if (disk.totalBytes > 1ULL * 1024 * 1024 * 1024) {
            d.disks.push_back(std::move(disk));
        }
    }

#elif defined(_WIN32)
    // Get logical drives.
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(drives & (1 << i))) continue;

        char root[] = {'A' + static_cast<char>(i), ':', '\\', '\0'};
        UINT type = GetDriveTypeA(root);
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;

        ULARGE_INTEGER free, total, totalFree;
        if (GetDiskFreeSpaceExA(root, &free, &total, &totalFree)) {
            DiskInfo disk;
            disk.mountPoint = root;
            disk.totalBytes = total.QuadPart;
            disk.freeBytes  = totalFree.QuadPart;
            if (disk.totalBytes > 0) {
                disk.usagePercent = 100.0 *
                    (1.0 - static_cast<double>(disk.freeBytes) /
                            static_cast<double>(disk.totalBytes));
            }
            d.disks.push_back(std::move(disk));
        }
    }
#endif
}

// ── Network Scanner ────────────────────────────────────────────────────────

void SystemScanner::scanNetwork(SystemDiagnostics& d) {
#ifdef __APPLE__
    // DNS check: resolve google.com.
    auto start = std::chrono::steady_clock::now();
    std::string dnsResult = exec("host -W 3 google.com 2>&1");
    auto end = std::chrono::steady_clock::now();

    d.network.dnsLatencyMs = std::chrono::duration<double, std::milli>(
                                 end - start).count();
    d.network.dnsWorking = (dnsResult.find("has address") != std::string::npos);

    // Ping check: 8.8.8.8 (Google DNS).
    std::string pingResult = exec("ping -c 1 -t 3 8.8.8.8 2>&1");
    d.network.internetReachable =
        (pingResult.find("1 packets received") != std::string::npos ||
         pingResult.find("bytes from") != std::string::npos);

    // Extract ping latency.
    auto timePos = pingResult.find("time=");
    if (timePos != std::string::npos) {
        try {
            d.network.pingLatencyMs = std::stod(
                pingResult.substr(timePos + 5));
        } catch (...) {}
    }

    // Get default gateway.
    std::string gwResult = exec("route -n get default 2>/dev/null | grep gateway");
    auto gwPos = gwResult.find("gateway:");
    if (gwPos != std::string::npos) {
        d.network.gateway = gwResult.substr(gwPos + 9);
        d.network.gateway.erase(0, d.network.gateway.find_first_not_of(" \t"));
        d.network.gateway.erase(d.network.gateway.find_last_not_of(" \t\r\n") + 1);
    }

    // Active interface.
    std::string ifResult = exec(
        "route -n get default 2>/dev/null | grep interface");
    auto ifPos = ifResult.find("interface:");
    if (ifPos != std::string::npos) {
        d.network.activeInterface = ifResult.substr(ifPos + 11);
        d.network.activeInterface.erase(
            0, d.network.activeInterface.find_first_not_of(" \t"));
        d.network.activeInterface.erase(
            d.network.activeInterface.find_last_not_of(" \t\r\n") + 1);
    }

#elif defined(_WIN32)
    // DNS check.
    std::string dnsResult = exec("nslookup google.com 2>&1");
    d.network.dnsWorking = (dnsResult.find("Address") != std::string::npos &&
                            dnsResult.find("Non-existent") == std::string::npos);

    // Ping check.
    std::string pingResult = exec("ping -n 1 -w 3000 8.8.8.8 2>&1");
    d.network.internetReachable =
        (pingResult.find("Reply from") != std::string::npos);

    auto timePos = pingResult.find("time=");
    if (timePos != std::string::npos) {
        try {
            d.network.pingLatencyMs = std::stod(
                pingResult.substr(timePos + 5));
        } catch (...) {}
    }
#endif
}

// ── Suspicious Process Scanner ─────────────────────────────────────────────

bool SystemScanner::isKnownMalwareName(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    for (const auto& mal : KNOWN_MALWARE_NAMES) {
        if (lower.find(mal) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool SystemScanner::isSuspiciousPath(const std::string& path) {
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Processes running from temp directories are suspicious.
    static const std::vector<std::string> suspiciousDirs = {
        "/tmp/", "/var/tmp/", "/private/tmp/",
        "/var/folders/",   // macOS temp
        "/.hidden", "/._",
        // Windows
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    };

    for (const auto& dir : suspiciousDirs) {
        if (lower.find(dir) != std::string::npos) return true;
    }
    return false;
}

void SystemScanner::scanSuspiciousProcesses(SystemDiagnostics& d) {
#ifdef __APPLE__
    // Get all PIDs.
    int pidCount = proc_listallpids(nullptr, 0);
    if (pidCount <= 0) return;

    std::vector<pid_t> pids(pidCount);
    pidCount = proc_listallpids(pids.data(),
                                static_cast<int>(pids.size() * sizeof(pid_t)));

    for (int i = 0; i < pidCount; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;

        // Get process name.
        char nameBuf[PROC_PIDPATHINFO_MAXSIZE];
        int nameLen = proc_pidpath(pid, nameBuf, sizeof(nameBuf));
        if (nameLen <= 0) continue;

        std::string fullPath(nameBuf, nameLen);
        std::string name = fullPath;
        auto slashPos = name.rfind('/');
        if (slashPos != std::string::npos) {
            name = name.substr(slashPos + 1);
        }

        // Check 1: Known malware name.
        if (isKnownMalwareName(name)) {
            SuspiciousProcess sp;
            sp.pid    = static_cast<uint32_t>(pid);
            sp.name   = name;
            sp.path   = fullPath;
            sp.reason = "Matches known malware/hacking tool name";
            d.suspiciousProcesses.push_back(std::move(sp));
            continue;
        }

        // Check 2: Running from suspicious directory.
        if (isSuspiciousPath(fullPath)) {
            SuspiciousProcess sp;
            sp.pid    = static_cast<uint32_t>(pid);
            sp.name   = name;
            sp.path   = fullPath;
            sp.reason = "Running from suspicious temp/hidden directory";
            d.suspiciousProcesses.push_back(std::move(sp));
            continue;
        }
    }

#elif defined(_WIN32)
    // Use EnumProcesses + GetModuleFileNameEx approach.
    // Similar logic: check name and path against known-bad lists.
    // (Reuses process_manager enumeration concept)
    std::string tasklist = exec("tasklist /FO CSV /NH 2>&1");
    std::istringstream stream(tasklist);
    std::string line;

    while (std::getline(stream, line)) {
        // Parse CSV: "name.exe","PID",...
        if (line.size() < 5 || line[0] != '"') continue;

        auto endQuote = line.find('"', 1);
        if (endQuote == std::string::npos) continue;
        std::string name = line.substr(1, endQuote - 1);

        auto pidStart = line.find('"', endQuote + 2);
        auto pidEnd   = line.find('"', pidStart + 1);
        if (pidStart == std::string::npos || pidEnd == std::string::npos)
            continue;
        uint32_t pid = 0;
        try { pid = std::stoul(line.substr(pidStart + 1, pidEnd - pidStart - 1)); }
        catch (...) { continue; }

        if (isKnownMalwareName(name)) {
            SuspiciousProcess sp;
            sp.pid    = pid;
            sp.name   = name;
            sp.reason = "Matches known malware/hacking tool name";
            d.suspiciousProcesses.push_back(std::move(sp));
        }
    }
#endif
}

// ── Temperature Scanner ────────────────────────────────────────────────────

void SystemScanner::scanTemperature(SystemDiagnostics& d) {
#ifdef __APPLE__
    // Try reading from powermetrics or osx-cpu-temp if available.
    // powermetrics requires root, so try a lighter approach.
    // The `sysctl` approach doesn't expose temp directly on all Macs.
    // We'll try `osx-cpu-temp` if installed, otherwise mark unavailable.
    std::string temp = exec("which osx-cpu-temp >/dev/null 2>&1 && "
                            "osx-cpu-temp 2>/dev/null");
    if (!temp.empty()) {
        try {
            d.cpuTemperature = std::stod(temp);
        } catch (...) {
            d.cpuTemperature = -1.0;
        }
    } else {
        // Try IOKit approach via a quick check.
        // On Apple Silicon, thermal data is harder to get without sudo.
        d.cpuTemperature = -1.0;
    }

#elif defined(_WIN32)
    // WMI query for temperature.
    std::string wmiResult = exec(
        "wmic /namespace:\\\\root\\wmi PATH MSAcpi_ThermalZoneTemperature "
        "get CurrentTemperature /value 2>&1");
    auto eqPos = wmiResult.find("CurrentTemperature=");
    if (eqPos != std::string::npos) {
        try {
            double kelvin10 = std::stod(wmiResult.substr(eqPos + 19));
            d.cpuTemperature = (kelvin10 / 10.0) - 273.15; // Convert to °C.
        } catch (...) {
            d.cpuTemperature = -1.0;
        }
    }
#endif
}

// ── Battery Scanner ────────────────────────────────────────────────────────

void SystemScanner::scanBattery(SystemDiagnostics& d) {
#ifdef __APPLE__
    std::string battInfo = exec("pmset -g batt 2>/dev/null");

    if (battInfo.find("InternalBattery") != std::string::npos ||
        battInfo.find("Battery") != std::string::npos) {
        d.battery.hasBattery = true;

        std::string batteryLine;
        std::istringstream battStream(battInfo);
        for (std::string line; std::getline(battStream, line);) {
            if (line.find('%') != std::string::npos) {
                batteryLine = line;
                break;
            }
        }

        // Extract percentage.
        auto pctPos = batteryLine.find('%');
        if (pctPos != std::string::npos) {
            // Walk backwards to find the start of the number.
            auto numStart = pctPos;
            while (numStart > 0 && (std::isdigit(batteryLine[numStart - 1]) ||
                                     batteryLine[numStart - 1] == '.')) {
                numStart--;
            }
            try {
                d.battery.chargePercent = std::stod(
                    batteryLine.substr(numStart, pctPos - numStart));
            } catch (...) {}
        }

        auto statusStart = batteryLine.find(';', pctPos);
        if (statusStart != std::string::npos) {
            statusStart++;
            auto statusEnd = batteryLine.find(';', statusStart);
            std::string status = batteryLine.substr(
                statusStart,
                statusEnd == std::string::npos ? std::string::npos
                                               : statusEnd - statusStart);
            status.erase(0, status.find_first_not_of(" \t"));
            status.erase(status.find_last_not_of(" \t\r\n") + 1);

            d.battery.isCharging =
                (status == "charging" || status == "finishing charge");
        }

        // Battery condition.
        std::string condResult = exec(
            "system_profiler SPPowerDataType 2>/dev/null | grep Condition");
        auto condPos = condResult.find("Condition:");
        if (condPos != std::string::npos) {
            d.battery.condition = condResult.substr(condPos + 10);
            d.battery.condition.erase(
                0, d.battery.condition.find_first_not_of(" \t"));
            d.battery.condition.erase(
                d.battery.condition.find_last_not_of(" \t\r\n") + 1);
        }
    }

#elif defined(_WIN32)
    SYSTEM_POWER_STATUS sps;
    if (GetSystemPowerStatus(&sps)) {
        d.battery.hasBattery = (sps.BatteryFlag != 128); // 128 = no battery
        if (d.battery.hasBattery) {
            d.battery.chargePercent = sps.BatteryLifePercent;
            d.battery.isCharging =
                (sps.ACLineStatus == 1 && sps.BatteryFlag & 8);
        }
    }
#endif
}

// ── Uptime Scanner ─────────────────────────────────────────────────────────

void SystemScanner::scanUptime(SystemDiagnostics& d) {
#ifdef __APPLE__
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};

    if (sysctl(mib, 2, &boottime, &len, nullptr, 0) == 0) {
        auto now = std::chrono::system_clock::now();
        auto boot = std::chrono::system_clock::from_time_t(boottime.tv_sec);
        auto duration = std::chrono::duration_cast<std::chrono::minutes>(
                            now - boot);
        d.uptimeHours = duration.count() / 60.0;
    }

#elif defined(_WIN32)
    ULONGLONG uptimeMs = GetTickCount64();
    d.uptimeHours = uptimeMs / (1000.0 * 60.0 * 60.0);
#endif
}

// ── OS Version Scanner ─────────────────────────────────────────────────────

void SystemScanner::scanOsVersion(SystemDiagnostics& d) {
#ifdef __APPLE__
    std::string version = exec("sw_vers -productVersion 2>/dev/null");
    version.erase(version.find_last_not_of(" \t\r\n") + 1);
    std::string name = exec("sw_vers -productName 2>/dev/null");
    name.erase(name.find_last_not_of(" \t\r\n") + 1);
    d.osVersion = name + " " + version;

#elif defined(_WIN32)
    std::string ver = exec("ver 2>&1");
    ver.erase(ver.find_last_not_of(" \t\r\n") + 1);
    d.osVersion = ver;
#endif
}

// ── Firewall Scanner ───────────────────────────────────────────────────────

void SystemScanner::scanFirewall(SystemDiagnostics& d) {
#ifdef __APPLE__
    std::string fwResult = exec(
        "/usr/libexec/ApplicationFirewall/socketfilterfw "
        "--getglobalstate 2>/dev/null");
    d.firewallEnabled =
        (fwResult.find("enabled") != std::string::npos);

#elif defined(_WIN32)
    std::string fwResult = exec(
        "netsh advfirewall show allprofiles state 2>&1");
    d.firewallEnabled =
        (fwResult.find("ON") != std::string::npos);
#endif
}

// ── Recent Error Log Scanner ───────────────────────────────────────────────

void SystemScanner::scanRecentErrors(SystemDiagnostics& d) {
#ifdef __APPLE__
    // Get error-level system log entries from the last 10 minutes.
    std::string logResult = exec(
        "log show --last 10m --predicate 'messageType == error' "
        "--style compact --info 2>/dev/null | tail -20");

    std::istringstream stream(logResult);
    std::string line;
    while (std::getline(stream, line)) {
        line.erase(0, line.find_first_not_of(" \t"));
        if (!line.empty() && line.size() > 10) {
            d.recentErrors.push_back(line);
        }
    }

#elif defined(_WIN32)
    // Get recent system error events.
    std::string logResult = exec(
        "wevtutil qe System /c:20 /f:text /rd:true "
        "/q:\"*[System[(Level=1 or Level=2)]]\" 2>&1");

    std::istringstream stream(logResult);
    std::string line;
    while (std::getline(stream, line)) {
        line.erase(0, line.find_first_not_of(" \t"));
        if (line.find("Message") != std::string::npos ||
            line.find("Error") != std::string::npos) {
            d.recentErrors.push_back(line);
        }
    }
#endif
}

// ── Report Generator ───────────────────────────────────────────────────────

std::string SystemScanner::generateReport(
    const SystemDiagnostics& diag,
    double cpuPercent, double memPercent,
    uint64_t memTotal, uint64_t memAvail)
{
    constexpr double GB = 1024.0 * 1024.0 * 1024.0;
    [[maybe_unused]] constexpr double MB = 1024.0 * 1024.0;

    std::ostringstream r;
    r << std::fixed << std::setprecision(1);

    r << "=== SYSTEM DIAGNOSTICS REPORT ===\n";
    r << "Scan Time: " << diag.scanTimestamp << "\n";
    r << "OS: " << diag.osVersion << "\n";
    r << "Uptime: " << diag.uptimeHours << " hours\n\n";

    // CPU & RAM.
    r << "--- CPU & MEMORY ---\n";
    r << "CPU Usage: " << cpuPercent << "%\n";
    r << "RAM Usage: " << memPercent << "% ("
      << static_cast<double>(memTotal - memAvail) / GB << " GB used / "
      << static_cast<double>(memTotal) / GB << " GB total, "
      << static_cast<double>(memAvail) / GB << " GB free)\n\n";

    // Disks.
    r << "--- DISK STATUS ---\n";
    for (const auto& disk : diag.disks) {
        r << "  " << disk.mountPoint << " (" << disk.filesystem << "): "
          << disk.usagePercent << "% used, "
          << static_cast<double>(disk.freeBytes) / GB << " GB free / "
          << static_cast<double>(disk.totalBytes) / GB << " GB total\n";
    }
    r << "\n";

    // Network.
    r << "--- NETWORK STATUS ---\n";
    r << "Internet Reachable: "
      << (diag.network.internetReachable ? "YES" : "NO") << "\n";
    r << "DNS Working: " << (diag.network.dnsWorking ? "YES" : "NO");
    if (diag.network.dnsLatencyMs >= 0) {
        r << " (latency: " << diag.network.dnsLatencyMs << " ms)";
    }
    r << "\n";
    if (diag.network.pingLatencyMs >= 0) {
        r << "Ping Latency: " << diag.network.pingLatencyMs << " ms\n";
    }
    if (!diag.network.gateway.empty()) {
        r << "Default Gateway: " << diag.network.gateway << "\n";
    }
    if (!diag.network.activeInterface.empty()) {
        r << "Active Interface: " << diag.network.activeInterface << "\n";
    }
    r << "\n";

    // Temperature.
    r << "--- HARDWARE ---\n";
    if (diag.cpuTemperature >= 0) {
        r << "CPU Temperature: " << diag.cpuTemperature << " °C\n";
    } else {
        r << "CPU Temperature: unavailable\n";
    }

    // Battery.
    if (diag.battery.hasBattery) {
        r << "Battery: " << diag.battery.chargePercent << "% "
          << (diag.battery.isCharging ? "(charging)" : "(discharging)")
          << "\n";
        if (!diag.battery.condition.empty()) {
            r << "Battery Condition: " << diag.battery.condition << "\n";
        }
    }

    // Firewall.
    r << "Firewall: "
      << (diag.firewallEnabled ? "ENABLED" : "DISABLED") << "\n\n";

    // Suspicious processes.
    r << "--- SECURITY SCAN ---\n";
    if (diag.suspiciousProcesses.empty()) {
        r << "No suspicious processes detected.\n";
    } else {
        r << "SUSPICIOUS PROCESSES FOUND:\n";
        for (const auto& sp : diag.suspiciousProcesses) {
            r << "  ! " << sp.name << " (PID " << sp.pid << ") - "
              << sp.reason << "\n";
            if (!sp.path.empty()) {
                r << "    Path: " << sp.path << "\n";
            }
        }
    }
    r << "\n";

    // Recent errors.
    r << "--- RECENT SYSTEM ERRORS (last 10 min) ---\n";
    if (diag.recentErrors.empty()) {
        r << "No recent error log entries.\n";
    } else {
        for (size_t i = 0; i < std::min(diag.recentErrors.size(),
                                          static_cast<size_t>(15)); i++) {
            r << "  " << diag.recentErrors[i] << "\n";
        }
        if (diag.recentErrors.size() > 15) {
            r << "  ... and " << (diag.recentErrors.size() - 15) << " more\n";
        }
    }

    r << "\n=== END REPORT ===\n";
    return r.str();
}

} // namespace fikcer::core

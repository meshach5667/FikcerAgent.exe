// ============================================================================
// FikcerAgent v2.0 – AI-Powered Self-Healing System Agent
// ============================================================================
// User-friendly autonomous agent that:
//   1. Monitors your computer's health (CPU, memory, disk, network)
//   2. Detects problems using heuristic + Gemini AI analysis
//   3. Fixes issues automatically (with your approval for risky actions)
//   4. Scans for malware, driver issues, and system errors
//
// Designed to be understandable by non-technical users.
// ============================================================================

#include "config.h"
#include "core/monitor.h"
#include "core/system_scanner.h"
#include "ai/anomaly_detector.h"
#include "ai/gemini_client.h"
#include "actions/process_manager.h"
#include "actions/auto_healer.h"
#include "actions/system_fixer.h"
#include "utils/logger.h"

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#ifdef _WIN32
#   include <Windows.h>
#endif

// ── ANSI colour helpers (for user-friendly output) ─────────────────────────
namespace clr {
    constexpr const char* RST     = "\033[0m";
    constexpr const char* BOLD    = "\033[1m";
    constexpr const char* RED     = "\033[1;31m";
    constexpr const char* GREEN   = "\033[1;32m";
    constexpr const char* YELLOW  = "\033[1;33m";
    constexpr const char* BLUE    = "\033[1;34m";
    constexpr const char* MAGENTA = "\033[1;35m";
    constexpr const char* CYAN    = "\033[1;36m";
    constexpr const char* DIM     = "\033[2m";
}

// ── Global shutdown flag ───────────────────────────────────────────────────
static std::atomic<bool> g_shutdownRequested{false};

#ifdef _WIN32
static BOOL WINAPI consoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_BREAK_EVENT:
            g_shutdownRequested.store(true, std::memory_order_release);
            return TRUE;
        default:
            return FALSE;
    }
}
#else
static void signalHandler(int /*sig*/) {
    g_shutdownRequested.store(true, std::memory_order_release);
}
#endif

// ── User-friendly helpers ──────────────────────────────────────────────────

static std::string formatBytes(uint64_t bytes) {
    constexpr double GB = 1024.0 * 1024.0 * 1024.0;
    constexpr double MB = 1024.0 * 1024.0;
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    if (bytes >= static_cast<uint64_t>(GB))
        oss << static_cast<double>(bytes) / GB << " GB";
    else
        oss << static_cast<double>(bytes) / MB << " MB";
    return oss.str();
}

static std::string healthBar(double percent) {
    if (percent < 50.0)  return std::string(clr::GREEN)  + "Good"       + clr::RST;
    if (percent < 75.0)  return std::string(clr::YELLOW) + "Moderate"   + clr::RST;
    if (percent < 90.0)  return std::string(clr::RED)    + "High"       + clr::RST;
    return std::string(clr::MAGENTA) + "Critical!" + clr::RST;
}

static void printDashboard(const fikcer::core::SystemStats& stats) {
    std::ostringstream o;
    o << std::fixed << std::setprecision(1);

    o << "\n" << clr::CYAN
      << "  +------------------------------------------------+\n"
      << "  |           Your Computer Health                  |\n"
      << "  +------------------------------------------------+\n"
      << clr::RST;

    o << "  |  " << clr::BOLD << "Processor (CPU)" << clr::RST
      << ":  " << std::setw(5) << stats.cpuUsagePercent << "%  "
      << healthBar(stats.cpuUsagePercent) << "\n";

    o << "  |  " << clr::BOLD << "Memory    (RAM)" << clr::RST
      << ":  " << std::setw(5) << stats.memUsagePercent << "%  "
      << healthBar(stats.memUsagePercent) << "\n";

    o << "  |  " << clr::DIM
      << "Using " << formatBytes(stats.memTotalBytes - stats.memAvailableBytes)
      << " of " << formatBytes(stats.memTotalBytes)
      << " (" << formatBytes(stats.memAvailableBytes) << " free)"
      << clr::RST << "\n";

    o << clr::CYAN
      << "  +------------------------------------------------+"
      << clr::RST << "\n";

    std::cout << o.str() << std::flush;

    std::ostringstream logLine;
    logLine << std::fixed << std::setprecision(1)
            << "CPU=" << stats.cpuUsagePercent << "% "
            << "RAM=" << stats.memUsagePercent << "% "
            << "(" << formatBytes(stats.memAvailableBytes) << " free)";
    fikcer::utils::Logger::instance().info(logLine.str());
}

// ── Translate technical anomaly into plain English ─────────────────────────

static std::string friendlyAnomaly(const fikcer::ai::Anomaly& a) {
    using fikcer::ai::AnomalyType;
    std::ostringstream m;
    switch (a.type) {
        case AnomalyType::CPU_SPIKE:
            m << "Your processor is working very hard ("
              << static_cast<int>(a.metricValue) << "% used). "
              << "Things may feel slow.";
            break;
        case AnomalyType::CPU_RAMP:
            m << "Processor usage is climbing quickly — something is "
              << "demanding more and more power.";
            break;
        case AnomalyType::MEMORY_SPIKE:
            m << "Your computer is running low on memory ("
              << static_cast<int>(a.metricValue) << "% used). "
              << "Apps may become unresponsive.";
            break;
        case AnomalyType::MEMORY_LEAK:
            m << "Memory usage keeps growing. An app might not be "
              << "releasing memory it no longer needs.";
            break;
        case AnomalyType::PROCESS_CPU_HOG:
            if (!a.relatedProcess.empty())
                m << "\"" << a.relatedProcess << "\" is using a lot of "
                  << "processor power (" << static_cast<int>(a.metricValue)
                  << "%).";
            else
                m << "A program is hogging the processor.";
            break;
        case AnomalyType::PROCESS_MEM_HOG:
            if (!a.relatedProcess.empty())
                m << "\"" << a.relatedProcess << "\" is using too much memory.";
            else
                m << "A program is using excessive memory.";
            break;
        case AnomalyType::SYSTEM_OVERLOAD:
            m << "Your computer is severely overloaded! Both processor "
              << "and memory are near their limits.";
            break;
        default:
            m << a.description;
            break;
    }
    return m.str();
}

static const char* sevColor(fikcer::ai::Severity s) {
    using S = fikcer::ai::Severity;
    switch (s) {
        case S::LOW:      return clr::DIM;
        case S::MEDIUM:   return clr::YELLOW;
        case S::HIGH:     return clr::RED;
        case S::CRITICAL: return clr::MAGENTA;
    }
    return clr::RST;
}

static const char* gemColor(const std::string& s) {
    if (s == "CRITICAL") return clr::MAGENTA;
    if (s == "HIGH")     return clr::RED;
    if (s == "MEDIUM")   return clr::YELLOW;
    return clr::DIM;
}

static std::string friendlyType(const std::string& t) {
    if (t == "DISK_SPACE")  return "Disk Space";
    if (t == "DISK_HEALTH") return "Disk Health";
    if (t == "NETWORK")     return "Network";
    if (t == "DNS")         return "Internet / DNS";
    if (t == "MALWARE")     return "Security Threat";
    if (t == "MEMORY")      return "Memory";
    if (t == "CPU")         return "Processor";
    if (t == "TEMPERATURE") return "Overheating";
    if (t == "BATTERY")     return "Battery";
    if (t == "DRIVER")      return "Driver Issue";
    if (t == "INTEGRITY")   return "System Files";
    if (t == "STARTUP")     return "Startup Programs";
    return t;
}

// ── Banner ─────────────────────────────────────────────────────────────────

static void printBanner() {
    std::cout << clr::CYAN << R"(
  +=========================================================+
  |                                                         |
  |   FikcerAgent v2.0                                      |
  |   AI-Powered Self-Healing System Agent                  |
  |                                                         |
  +---------------------------------------------------------+
  |                                                         |
  |   [ok] Health Monitor   - Watches CPU & Memory          |
  |   [ok] Problem Detector - Finds issues automatically    |
  |   [ok] Gemini AI Brain  - Deep system analysis          |
  |   [ok] Malware Scanner  - Detects suspicious programs   |
  |   [ok] Auto-Fixer       - Repairs problems for you      |
  |                                                         |
  |   Press Ctrl+C to stop the agent safely.                |
  |                                                         |
  +=========================================================+
)" << clr::RST << std::endl;
}

// ============================================================================
// main
// ============================================================================
int main() {
    using namespace fikcer;

    // ── 1. Signal handling ─────────────────────────────────────────────────
#ifdef _WIN32
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
    SetConsoleOutputCP(CP_UTF8);
#else
    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);
#endif

    printBanner();

    // ── 2. Logger ──────────────────────────────────────────────────────────
    auto& logger = utils::Logger::instance();
    if (!logger.init(std::string(config::LOG_DIRECTORY),
                     config::LOG_FILE_PREFIX,
                     config::MAX_LOG_FILE_SIZE,
                     config::MAX_LOG_FILES,
                     utils::LogLevel::INFO)) {
        std::cerr << clr::RED << "  [!] Could not start the logging system.\n"
                  << clr::RST;
        return EXIT_FAILURE;
    }
    logger.info("FikcerAgent v2.0 starting");

    // ── 3. System Monitor ──────────────────────────────────────────────────
    std::cout << clr::DIM << "  Starting health monitor..." << clr::RST << "\n";
    core::Monitor monitor;
    monitor.setCallback(printDashboard);
    if (!monitor.start(config::MONITOR_INTERVAL_MS)) {
        std::cerr << clr::RED
                  << "  [!] Could not start the health monitor.\n"
                  << clr::RST;
        return EXIT_FAILURE;
    }

    // ── 4. Process Manager ─────────────────────────────────────────────────
    std::cout << clr::DIM << "  Starting process manager..." << clr::RST << "\n";
    actions::ProcessManager procMgr;
#ifdef _WIN32
    procMgr.addToWhitelist("notepad.exe");
    procMgr.addToWhitelist("explorer.exe");
    procMgr.addToWhitelist("calc.exe");
#elif defined(__APPLE__)
    procMgr.addToWhitelist("TextEdit");
    procMgr.addToWhitelist("Calculator");
    procMgr.addToWhitelist("Notes");
#endif

    procMgr.setHungCallback([](const actions::ProcessInfo& info) {
        std::cout << "\n" << clr::RED
                  << "  [!] \"" << info.name
                  << "\" appears to be frozen (not responding)."
                  << clr::RST << "\n";
        utils::Logger::instance().warn(
            "Hung process: " + info.name + " PID=" +
            std::to_string(info.pid));
    });

    if (!procMgr.start(config::PROCESS_SCAN_INTERVAL_MS)) {
        std::cerr << clr::RED
                  << "  [!] Could not start the process manager.\n"
                  << clr::RST;
        monitor.stop();
        return EXIT_FAILURE;
    }

    // ── 5. Anomaly Detector + Auto-Healer ─────────────────────────────────
    std::cout << clr::DIM << "  Starting problem detector..."
              << clr::RST << "\n";

    ai::AnomalyDetector detector;
    actions::AutoHealer  healer(procMgr);

    // Limit noisy output — show only top 5 issues per cycle.
    static constexpr unsigned int MAX_SHOWN = 5;

    detector.setCallback([&healer](const std::vector<ai::Anomaly>& anomalies) {
        if (anomalies.empty()) return;

        // Sort by severity (highest first).
        auto sorted = anomalies;
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) {
                      return static_cast<int>(a.severity) >
                             static_cast<int>(b.severity);
                  });

        std::cout << "\n" << clr::YELLOW
                  << "  --- Problem Detector: " << anomalies.size()
                  << " issue" << (anomalies.size() > 1 ? "s" : "")
                  << " found ---" << clr::RST << "\n";

        unsigned int shown = 0;
        for (const auto& a : sorted) {
            if (shown >= MAX_SHOWN) break;
            shown++;
            std::cout << "  " << sevColor(a.severity)
                      << "  " << friendlyAnomaly(a)
                      << clr::RST << "\n";
        }
        if (sorted.size() > MAX_SHOWN) {
            std::cout << clr::DIM << "  ... and "
                      << (sorted.size() - MAX_SHOWN)
                      << " more (see log file for details)"
                      << clr::RST << "\n";
        }

        // Let healer act.
        auto records = healer.handleAnomalies(anomalies);
        for (const auto& r : records) {
            if (r.action != actions::HealAction::LOG_ONLY &&
                r.action != actions::HealAction::NONE) {
                std::cout << "  " << clr::GREEN
                          << "  [fix] " << r.description
                          << clr::RST << "\n";
            }
        }
    });

    healer.setCallback([](const actions::HealRecord& rec) {
        utils::Logger::instance().info(
            "Heal: " + rec.description +
            " (ok=" + (rec.success ? "yes" : "no") + ")");
    });

    // ── 6. Gemini AI Client ───────────────────────────────────────────────
    std::cout << clr::DIM << "  Connecting to Gemini AI..."
              << clr::RST << "\n";

    ai::GeminiClient gemini;
    bool geminiReady = gemini.init();

    if (geminiReady) {
        std::cout << clr::GREEN
                  << "  [ok] Gemini AI connected (model: "
                  << gemini.modelName() << ")"
                  << clr::RST << "\n";
    } else {
        std::cout << clr::YELLOW
                  << "  [!] Gemini AI not available — using local "
                  << "detection only.\n"
                  << "      To enable: set FIKCER_GEMINI_API_KEY "
                  << "environment variable.\n"
                  << clr::RST;
    }

    // ── 7. System Scanner & Fixer ─────────────────────────────────────────
    core::SystemScanner scanner;
    actions::SystemFixer fixer;

    fixer.setCallback([](const actions::FixRecord& rec) {
        utils::Logger::instance().info(
            "Fix [" + rec.problemType + "]: " + rec.fixApplied +
            " (ok=" + (rec.success ? "yes" : "no") + ")");
    });

    // ── 8. Ready ──────────────────────────────────────────────────────────
    std::cout << "\n" << clr::GREEN << clr::BOLD
              << "  FikcerAgent is now protecting your computer!"
              << clr::RST << "\n"
              << clr::DIM << "  Press Ctrl+C to stop.\n"
              << clr::RST << "\n";

    logger.info("All modules running.");

    // ── 9. Main loop ──────────────────────────────────────────────────────
    auto lastHeuristic = std::chrono::steady_clock::now();
    // Schedule first deep scan ~10s after start.
    auto lastDeep = std::chrono::steady_clock::now()
                    - std::chrono::milliseconds(
                          config::DEEP_SCAN_INTERVAL_MS - 10000);

    while (!g_shutdownRequested.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto now = std::chrono::steady_clock::now();

        // ── Heuristic pass ────────────────────────────────────────────────
        auto hElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - lastHeuristic).count();
        if (hElapsed >= config::AI_SCAN_INTERVAL_MS) {
            lastHeuristic = now;
            auto procs  = ai::AnomalyDetector::sampleProcessResources();
            auto latest = monitor.latestStats();
            detector.feed(latest, procs);
        }

        // ── Deep scan + Gemini ────────────────────────────────────────────
        if (geminiReady) {
            auto dElapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - lastDeep).count();

            if (dElapsed >= config::DEEP_SCAN_INTERVAL_MS) {
                lastDeep = now;

                std::cout << "\n" << clr::BLUE
                          << "  [scan] Running deep system check with Gemini AI..."
                          << clr::RST << "\n";

                auto diag   = scanner.scan();
                auto latest = monitor.latestStats();

                std::string report = core::SystemScanner::generateReport(
                    diag, latest.cpuUsagePercent, latest.memUsagePercent,
                    latest.memTotalBytes, latest.memAvailableBytes);

                logger.info("Deep scan complete, querying Gemini...");

                auto problems = gemini.analyseSystem(report);

                if (problems.empty()) {
                    std::cout << clr::GREEN
                              << "  [ok] Gemini AI: Everything looks healthy!"
                              << clr::RST << "\n";
                } else {
                    std::cout << "\n" << clr::BOLD
                              << "  Gemini AI found " << problems.size()
                              << " issue" << (problems.size() > 1 ? "s" : "")
                              << ":" << clr::RST << "\n\n";

                    for (const auto& p : problems) {
                        std::cout << "  " << gemColor(p.severity)
                                  << "  [" << p.severity << "] "
                                  << clr::BOLD << friendlyType(p.type)
                                  << clr::RST << ": " << p.description
                                  << "\n";
                        if (p.fixType != "NONE" && !p.fixDescription.empty())
                            std::cout << clr::GREEN
                                      << "     -> Fix: " << p.fixDescription
                                      << clr::RST << "\n";
                    }

                    // Apply safe fixes.
                    auto fixRecs = fixer.fixProblems(problems);

                    unsigned int ok = 0, fail = 0;
                    for (const auto& fr : fixRecs) {
                        if (fr.success && !fr.dryRun &&
                            fr.fixApplied.find("No auto-fix") ==
                                std::string::npos)
                            ok++;
                        else if (!fr.success)
                            fail++;
                    }

                    if (ok > 0)
                        std::cout << "\n" << clr::GREEN
                                  << "  [ok] " << ok << " fix"
                                  << (ok > 1 ? "es" : "")
                                  << " applied!" << clr::RST << "\n";
                    if (fail > 0)
                        std::cout << clr::YELLOW
                                  << "  [!] " << fail << " fix"
                                  << (fail > 1 ? "es" : "")
                                  << " could not be applied "
                                  << "(may need admin permissions)."
                                  << clr::RST << "\n";
                }

                // Local scan warnings.
                if (!diag.suspiciousProcesses.empty()) {
                    std::cout << "\n" << clr::RED
                              << "  [security] Found "
                              << diag.suspiciousProcesses.size()
                              << " suspicious program"
                              << (diag.suspiciousProcesses.size() > 1
                                      ? "s" : "") << ":"
                              << clr::RST << "\n";
                    for (const auto& sp : diag.suspiciousProcesses)
                        std::cout << clr::RED << "    - \""
                                  << sp.name << "\": " << sp.reason
                                  << clr::RST << "\n";
                }
                if (!diag.network.internetReachable)
                    std::cout << clr::YELLOW
                              << "  [!] No internet connection detected."
                              << clr::RST << "\n";
                if (!diag.firewallEnabled)
                    std::cout << clr::YELLOW
                              << "  [!] Your firewall is turned off. "
                              << "Consider enabling it."
                              << clr::RST << "\n";
            }
        }

#ifdef _WIN32
        if (GetAsyncKeyState(VK_RETURN) & 0x0001)
            g_shutdownRequested.store(true, std::memory_order_release);
#endif
    }

    // ── 10. Shutdown ──────────────────────────────────────────────────────
    std::cout << "\n" << clr::CYAN
              << "  Shutting down FikcerAgent..." << clr::RST << "\n";
    logger.info("FikcerAgent shutting down");

    std::cout << "\n" << clr::BOLD
              << "  Session Summary:" << clr::RST << "\n"
              << "    Processes healed  : "
              << healer.totalTerminations() << " terminated, "
              << healer.totalRestarts() << " restarted\n"
              << "    Memory cleanups   : "
              << healer.totalPurgeCaches() << "\n"
              << "    System fixes      : "
              << fixer.totalFixesApplied() << " applied, "
              << fixer.totalFixesFailed() << " failed\n"
              << "    Threats stopped   : "
              << fixer.totalKills() << "\n";

    procMgr.stop();
    monitor.stop();
    logger.shutdown();

    std::cout << "\n" << clr::GREEN
              << "  FikcerAgent stopped. Stay safe!\n"
              << clr::RST << "\n";
    return EXIT_SUCCESS;
}

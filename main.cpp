// ============================================================================
// FikcerAgent v2.0 – AI-Powered Self-Healing System Agent
// ============================================================================
// Entry point that launches either:
//   • Desktop GUI (default)  – Dear ImGui window with dashboard, alerts, AI
//   • CLI mode (--cli flag)  – Original terminal-based output
// ============================================================================

#include "gui/app.h"           // GUI mode
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
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#ifdef _WIN32
#   include <Windows.h>
#endif

// ============================================================================
// GUI mode (default)
// ============================================================================
static int runGui() {
    fikcer::gui::App app;
    if (!app.init()) {
        std::cerr << "Failed to initialise FikcerAgent GUI.\n";
        return EXIT_FAILURE;
    }
    app.run();
    return EXIT_SUCCESS;
}

// ============================================================================
// CLI mode (--cli flag) — original terminal UI
// ============================================================================

// ── ANSI colour helpers ────────────────────────────────────────────────────
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

static std::string friendlyAnomaly(const fikcer::ai::Anomaly& a) {
    using fikcer::ai::AnomalyType;
    std::ostringstream m;
    switch (a.type) {
        case AnomalyType::CPU_SPIKE:
            m << "Your processor is working very hard ("
              << static_cast<int>(a.metricValue) << "% used).";
            break;
        case AnomalyType::CPU_RAMP:
            m << "Processor usage is climbing quickly.";
            break;
        case AnomalyType::MEMORY_SPIKE:
            m << "Running low on memory ("
              << static_cast<int>(a.metricValue) << "% used).";
            break;
        case AnomalyType::MEMORY_LEAK:
            m << "Memory keeps growing — an app may have a leak.";
            break;
        case AnomalyType::PROCESS_CPU_HOG:
            if (!a.relatedProcess.empty())
                m << "\"" << a.relatedProcess << "\" hogging processor ("
                  << static_cast<int>(a.metricValue) << "%).";
            else
                m << "A program is hogging the processor.";
            break;
        case AnomalyType::PROCESS_MEM_HOG:
            if (!a.relatedProcess.empty())
                m << "\"" << a.relatedProcess << "\" using too much memory.";
            else
                m << "A program is using excessive memory.";
            break;
        case AnomalyType::SYSTEM_OVERLOAD:
            m << "Computer is severely overloaded!";
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

static const char* gemColorCli(const std::string& s) {
    if (s == "CRITICAL") return clr::MAGENTA;
    if (s == "HIGH")     return clr::RED;
    if (s == "MEDIUM")   return clr::YELLOW;
    return clr::DIM;
}

static std::string friendlyTypeCli(const std::string& t) {
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

static int runCli() {
    using namespace fikcer;

#ifdef _WIN32
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
    SetConsoleOutputCP(CP_UTF8);
#else
    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);
#endif

    std::cout << clr::CYAN << R"(
  +=========================================================+
  |  FikcerAgent v2.0  –  CLI Mode                         |
  |  AI-Powered Self-Healing System Agent                   |
  |  Press Ctrl+C to stop.                                  |
  +=========================================================+
)" << clr::RST << std::endl;

    auto& logger = utils::Logger::instance();
    if (!logger.init(std::string(config::LOG_DIRECTORY),
                     config::LOG_FILE_PREFIX,
                     config::MAX_LOG_FILE_SIZE,
                     config::MAX_LOG_FILES,
                     utils::LogLevel::INFO)) {
        std::cerr << clr::RED << "  [!] Could not start logging.\n" << clr::RST;
        return EXIT_FAILURE;
    }
    logger.info("FikcerAgent v2.0 CLI starting");

    core::Monitor monitor;
    monitor.setCallback(printDashboard);
    if (!monitor.start(config::MONITOR_INTERVAL_MS)) {
        std::cerr << clr::RED << "  [!] Health monitor failed.\n" << clr::RST;
        return EXIT_FAILURE;
    }

    actions::ProcessManager procMgr;
#ifdef __APPLE__
    procMgr.addToWhitelist("TextEdit");
    procMgr.addToWhitelist("Calculator");
    procMgr.addToWhitelist("Notes");
#endif
    procMgr.setHungCallback([](const actions::ProcessInfo& info) {
        std::cout << clr::RED << "  [!] \"" << info.name
                  << "\" frozen.\n" << clr::RST;
    });
    procMgr.start(config::PROCESS_SCAN_INTERVAL_MS);

    ai::AnomalyDetector detector;
    actions::AutoHealer  healer(procMgr);
    static constexpr unsigned int MAX_SHOWN = 5;

    detector.setCallback([&healer](const std::vector<ai::Anomaly>& anomalies) {
        if (anomalies.empty()) return;
        auto sorted = anomalies;
        std::sort(sorted.begin(), sorted.end(),
                  [](auto& a, auto& b) {
                      return static_cast<int>(a.severity) >
                             static_cast<int>(b.severity);
                  });
        std::cout << "\n" << clr::YELLOW << "  --- " << anomalies.size()
                  << " issue(s) ---" << clr::RST << "\n";
        unsigned int shown = 0;
        for (const auto& a : sorted) {
            if (shown++ >= MAX_SHOWN) break;
            std::cout << "  " << sevColor(a.severity)
                      << "  " << friendlyAnomaly(a)
                      << clr::RST << "\n";
        }
        healer.handleAnomalies(anomalies);
    });

    ai::GeminiClient gemini;
    bool geminiReady = gemini.init();
    core::SystemScanner scanner;
    actions::SystemFixer fixer;

    std::cout << clr::GREEN << "  FikcerAgent running (CLI mode).\n"
              << clr::RST;

    auto lastH = std::chrono::steady_clock::now();
    auto lastD = std::chrono::steady_clock::now()
                 - std::chrono::milliseconds(config::DEEP_SCAN_INTERVAL_MS - 10000);

    while (!g_shutdownRequested.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto now = std::chrono::steady_clock::now();

        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastH).count()
            >= config::AI_SCAN_INTERVAL_MS) {
            lastH = now;
            detector.feed(monitor.latestStats(),
                          ai::AnomalyDetector::sampleProcessResources());
        }

        if (geminiReady &&
            std::chrono::duration_cast<std::chrono::milliseconds>(now - lastD).count()
            >= config::DEEP_SCAN_INTERVAL_MS) {
            lastD = now;
            std::cout << clr::BLUE << "  [scan] Deep system check...\n" << clr::RST;
            auto diag = scanner.scan();
            auto lat  = monitor.latestStats();
            auto report = core::SystemScanner::generateReport(
                diag, lat.cpuUsagePercent, lat.memUsagePercent,
                lat.memTotalBytes, lat.memAvailableBytes);
            auto problems = gemini.analyseSystem(report);
            if (problems.empty()) {
                std::cout << clr::GREEN << "  [ok] All healthy!\n" << clr::RST;
            } else {
                for (const auto& p : problems) {
                    std::cout << "  " << gemColorCli(p.severity)
                              << "[" << p.severity << "] "
                              << friendlyTypeCli(p.type) << ": "
                              << p.description << clr::RST << "\n";
                }
                fixer.fixProblems(problems);
            }
        }
    }

    std::cout << clr::CYAN << "  Shutting down...\n" << clr::RST;
    procMgr.stop();
    monitor.stop();
    logger.shutdown();
    std::cout << clr::GREEN << "  FikcerAgent stopped. Stay safe!\n" << clr::RST;
    return EXIT_SUCCESS;
}

// ============================================================================
// main – dispatch to GUI or CLI
// ============================================================================
int main(int argc, char* argv[]) {
    bool cliMode = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--cli") == 0 ||
            std::strcmp(argv[i], "-c")    == 0) {
            cliMode = true;
        }
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h")     == 0) {
            std::cout << "FikcerAgent v2.0 – AI System Guardian\n\n"
                      << "Usage: FikcerAgent [options]\n\n"
                      << "Options:\n"
                      << "  --cli, -c   Run in terminal (CLI) mode\n"
                      << "  --help, -h  Show this help\n\n"
                      << "Default: Opens the desktop GUI.\n";
            return EXIT_SUCCESS;
        }
    }

    return cliMode ? runCli() : runGui();
}

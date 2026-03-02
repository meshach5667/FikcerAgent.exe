//
// FikcerAgent – Entry Point
// 
// Ties together the three modules:
//   1. Logger   (utils)   – initialised first so every module can log.
//   2. Monitor  (core)    – background thread printing CPU / RAM stats.
//   3. Process Manager    – background thread scanning for hung apps.
//
// The main thread blocks on user input so the console stays interactive;
// pressing Enter (or Ctrl+C) triggers a graceful shutdown.
// 

#include "config.h"
#include "core/monitor.h"
#include "actions/process_manager.h"
#include "utils/logger.h"

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#ifdef _WIN32
#   include <Windows.h>
#endif

// ── Global shutdown flag
static std::atomic<bool> g_shutdownRequested{false};

// ── Signal / console handler
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

// ── Console helpers 
/// Format bytes into a human-readable string (e.g. "7.4 GB").
static std::string formatBytes(uint64_t bytes) {
    constexpr double GB = 1024.0 * 1024.0 * 1024.0;
    constexpr double MB = 1024.0 * 1024.0;

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);

    if (bytes >= static_cast<uint64_t>(GB)) {
        oss << static_cast<double>(bytes) / GB << " GB";
    } else {
        oss << static_cast<double>(bytes) / MB << " MB";
    }
    return oss.str();
}

/// Pretty-print a SystemStats snapshot to the console and log file.
static void printStats(const fikcer::core::SystemStats& stats) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    oss << "  System Stats \n"
        << "│  CPU Usage  : " << std::setw(6) << stats.cpuUsagePercent
        << " %"
        << std::string(18 - std::to_string(
               static_cast<int>(stats.cpuUsagePercent)).size(), ' ')
        << "│\n"
        << "│  RAM Usage  : " << std::setw(6) << stats.memUsagePercent
        << " %"
        << std::string(18 - std::to_string(
               static_cast<int>(stats.memUsagePercent)).size(), ' ')
        << "│\n"
        << "│  RAM Total  : " << std::setw(10)
        << formatBytes(stats.memTotalBytes)
        << std::string(13 - formatBytes(stats.memTotalBytes).size(), ' ')
        << "│\n"
        << "│  RAM Avail  : " << std::setw(10)
        << formatBytes(stats.memAvailableBytes)
        << std::string(13 - formatBytes(stats.memAvailableBytes).size(), ' ')
        << "│\n"
        << " ---";

    std::cout << oss.str() << "\n\n";

    // Also log a compact one-liner.
    std::ostringstream logLine;
    logLine << std::fixed << std::setprecision(1)
            << "CPU=" << stats.cpuUsagePercent << "% "
            << "RAM=" << stats.memUsagePercent << "% "
            << "(" << formatBytes(stats.memAvailableBytes) << " free)";
    fikcer::utils::Logger::instance().info(logLine.str());

    // Threshold warnings.
    if (stats.cpuUsagePercent >= fikcer::config::CPU_WARNING_THRESHOLD) {
        fikcer::utils::Logger::instance().warn(
            "CPU usage is critically high: " +
            std::to_string(static_cast<int>(stats.cpuUsagePercent)) + "%");
    }
    if (stats.memUsagePercent >= fikcer::config::MEMORY_WARNING_THRESHOLD) {
        fikcer::utils::Logger::instance().warn(
            "Memory usage is critically high: " +
            std::to_string(static_cast<int>(stats.memUsagePercent)) + "%");
    }
}

// Banner 

static void printBanner() {
    std::cout <<
R"(
  ╔══════════════════════════════════════════════════╗
  ║    FikcerAgent v1.0 – Self-Healing System Agent   ║
  ╠═══════════════════════════════════════════════════╣
  ║  Modules:                                         ║
  ║    [✓] System Monitor  (CPU + RAM)                ║
  ║    [✓] Process Manager (hung-app detection)       ║
  ║    [✓] Logger          (rotating file log)        ║
  ║                                                   ║
  ║  Press Ctrl+C or Enter to shut down gracefully.   ║
  -----------------------------------------------------
)" << std::endl;
}

// 
// main
// 
int main() {
    using namespace fikcer;

    // ── 1. Register signal / console handler
#ifdef _WIN32
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
    // Enable UTF-8 console output.
    SetConsoleOutputCP(CP_UTF8);
#else
    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);
#endif

    printBanner();

    // ── 2. Initialise Logger 
    auto& logger = utils::Logger::instance();

    if (!logger.init(
            std::string(config::LOG_DIRECTORY),
            config::LOG_FILE_PREFIX,
            config::MAX_LOG_FILE_SIZE,
            config::MAX_LOG_FILES,
            utils::LogLevel::INFO)) {
        std::cerr << "[FATAL] Logger initialisation failed.\n";
        return EXIT_FAILURE;
    }

    logger.info("FikcerAgent starting ");

    // ── 3. Start System Monitor
    core::Monitor monitor;
    monitor.setCallback(printStats);

    if (!monitor.start(config::MONITOR_INTERVAL_MS)) {
        logger.fatal("Failed to start system monitor.");
        return EXIT_FAILURE;
    }

    // ── 4. Configure & start Process Manager 
    actions::ProcessManager procMgr;

    // Whitelist: add the executables you want auto-restarted here.
    // Adjust to your environment and OS.
#ifdef _WIN32
    procMgr.addToWhitelist("notepad.exe");
    procMgr.addToWhitelist("explorer.exe");
    procMgr.addToWhitelist("calc.exe");
    // Add more with: procMgr.addToWhitelist("yourapp.exe");
#elif defined(__APPLE__)
    procMgr.addToWhitelist("TextEdit");
    procMgr.addToWhitelist("Calculator");
    procMgr.addToWhitelist("Notes");
    // Add more with: procMgr.addToWhitelist("YourApp");
#endif

    procMgr.setHungCallback([](const actions::ProcessInfo& info) {
        std::ostringstream oss;
        oss << "[!] Hung process detected: " << info.name
            << " (PID " << info.pid << ")";
        std::cout << "\033[1;31m" << oss.str() << "\033[0m\n";  // Red text.
        utils::Logger::instance().warn(oss.str());
    });

    if (!procMgr.start(config::PROCESS_SCAN_INTERVAL_MS)) {
        logger.fatal("Failed to start process manager.");
        monitor.stop();
        return EXIT_FAILURE;
    }

    // ── 5. Main-thread idle loop 
    // Block until the user presses Enter or a signal arrives.
    logger.info("All modules running. Waiting for shutdown signal...");

    while (!g_shutdownRequested.load(std::memory_order_acquire)) {
        // Check every 500 ms so we react to Ctrl+C promptly.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Also check if stdin has data (Enter pressed) – non-blocking peek.
#ifdef _WIN32
        if (GetAsyncKeyState(VK_RETURN) & 0x0001) {
            g_shutdownRequested.store(true, std::memory_order_release);
        }
#endif
    }

    // ── 6. Graceful shutdown 
    std::cout << "\n[*] Shutting down FikcerAgent...\n";
    logger.info(" FikcerAgent shutting down ");

    procMgr.stop();
    monitor.stop();
    logger.shutdown();

    std::cout << "[*] Mesh's Machine says Goodbye.\n";
    return EXIT_SUCCESS;
}

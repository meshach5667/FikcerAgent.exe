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



// ── ANSI colour helpers ────────────────────────────────────────────────────
namespace clr {
    constexpr const char* RST     = "\033[0m";
    constexpr const char* BOLD    = "\033[1m";
    constexpr const char* RED     = "\033[1;31m";
    constexpr const char* GREEN   = "\033[1;32m";
    constexpr const char* YELLOW  = "\033[1;33m";
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

// END HELPERS

#include "agent/agent.h"

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

    agent::Agent coreAgent;
    
    // Register event callback before starting
    coreAgent.setEventCallback([](const agent::AgentEvent& ev) {
        if (ev.type == agent::AgentEvent::HEALTH_UPDATE) {
            std::cout << "\n" << clr::CYAN << "  +--- " << ev.message << " ---+" << clr::RST << "\n";
        } else if (ev.type == agent::AgentEvent::ALERT || ev.type == agent::AgentEvent::APPROVAL_NEEDED) {
            std::cout << "  " << clr::YELLOW << "[!] " << ev.message << clr::RST << "\n";
        } else if (ev.type == agent::AgentEvent::ACTION_TAKEN) {
            std::cout << "  " << clr::GREEN << "[*] " << ev.message << clr::RST << "\n";
        } else if (ev.severity == "error" || ev.severity == "critical") {
            std::cout << "  " << clr::RED << "[E] " << ev.message << clr::RST << "\n";
        } else if (ev.severity == "warn") {
            std::cout << "  " << clr::YELLOW << "[W] " << ev.message << clr::RST << "\n";
        } else {
            // normal info logging is handled by logger, but we can print some to CLI
            std::cout << "  " << clr::DIM << "[i] " << ev.message << clr::RST << "\n";
        }
    });

    if (!coreAgent.init()) {
        std::cerr << clr::RED << "  [!] Failed to initialise FikcerAgent.\n" << clr::RST;
        return EXIT_FAILURE;
    }

    if (!coreAgent.start()) {
        std::cerr << clr::RED << "  [!] Failed to start agent loop.\n" << clr::RST;
        return EXIT_FAILURE;
    }

    std::cout << clr::GREEN << "  FikcerAgent running (CLI mode).\n" << clr::RST;

    while (!g_shutdownRequested.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Check for pending approvals and auto-approve in CLI for testing
        // Or we could prompt the user. For simplicity, just list them.
        auto approvals = coreAgent.pendingApprovals();
        for (const auto& req : approvals) {
            std::cout << clr::YELLOW << "  [APPROVAL NEEDED] " 
                      << req.plan.recommendedAction << " (" << req.impact.impactDescription << ")\n"
                      << "  Reasoning: " << req.plan.reasoning << "\n"
                      << "  Auto-approving in CLI mode for demonstration..." << clr::RST << "\n";
            coreAgent.approveAction(req.id);
        }
    }

    std::cout << clr::CYAN << "  Shutting down...\n" << clr::RST;
    coreAgent.stop();
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

// ============================================================================
// FikcerAgent – Dear ImGui Desktop GUI Application

// Renders a user-friendly desktop window with:
//   • Dashboard   – real-time CPU/RAM gauges + health status
//   • Alerts      – colour-coded anomaly list in plain English
//   • Gemini AI   – deep-scan results, fix recommendations, approve/deny
//   • Security    – suspicious processes, firewall, network
//   • Log Viewer  – scrollable recent log lines
//
// Backed by Dear ImGui + GLFW + OpenGL 3.

#pragma once

#include "core/monitor.h"
#include "core/system_scanner.h"
#include "ai/anomaly_detector.h"
#include "ai/gemini_client.h"
#include "actions/process_manager.h"
#include "actions/auto_healer.h"
#include "actions/system_fixer.h"

#include <deque>
#include <mutex>
#include <string>
#include <vector>

struct GLFWwindow;   // Forward declaration – no GLFW include in header.

namespace fikcer::gui {

// ── Log ring buffer entry ──────────────────────────────────────────────────
struct LogEntry {
    enum Level { INFO, WARN, ERR };
    Level       level = INFO;
    std::string text;
};

// ── Pending Gemini fix (awaiting user approval) ────────────────────────────
struct PendingFix {
    ai::GeminiProblem problem;
    bool               approved  = false;
    bool               denied    = false;
    bool               applied   = false;
    bool               succeeded = false;
};

// ── Application ────────────────────────────────────────────────────────────
class App final {
public:
    App();
    ~App();

    App(const App&) = delete;
    App& operator=(const App&) = delete;

    /// Initialise GLFW + ImGui + all backend modules.
    /// @return true on success.
    bool init();

    /// Run the main rendering loop (blocking).
    void run();

    /// Request orderly shutdown (can be called from signal handler).
    void requestShutdown();

private:
    // ── GLFW / ImGui lifecycle ─────────────────────────────────────────────
    bool initWindow();
    void initImGui();
    void shutdownImGui();
    void newFrame();
    void render();

    // ── UI tabs ────────────────────────────────────────────────────────────
    void drawDashboard();
    void drawAlerts();
    void drawGeminiPanel();
    void drawSecurityPanel();
    void drawLogViewer();

    // ── UI helpers ─────────────────────────────────────────────────────────
    void drawHealthGauge(const char* label, float value, float warnAt, float critAt);
    void pushLog(LogEntry::Level lvl, const std::string& msg);

    // ── Backend callbacks ──────────────────────────────────────────────────
    void onStats(const core::SystemStats& stats);
    void onAnomalies(const std::vector<ai::Anomaly>& anomalies);

    // ── Window state ───────────────────────────────────────────────────────
    GLFWwindow* window_ = nullptr;
    bool        shutdownRequested_ = false;

    // ── Backend modules ────────────────────────────────────────────────────
    core::Monitor              monitor_;
    actions::ProcessManager    procMgr_;
    ai::AnomalyDetector        detector_;
    actions::AutoHealer        healer_{procMgr_};
    ai::GeminiClient           gemini_;
    bool                       geminiReady_ = false;
    core::SystemScanner        scanner_;
    actions::SystemFixer       fixer_;

    // ── Shared state (protected by mutex_) ─────────────────────────────────
    mutable std::mutex mutex_;

    // Dashboard
    core::SystemStats latestStats_{};
    static constexpr std::size_t MAX_GRAPH_SAMPLES = 120;
    std::deque<float> cpuHistory_;
    std::deque<float> memHistory_;

    // Alerts
    static constexpr std::size_t MAX_ALERTS = 50;
    std::deque<ai::Anomaly> alerts_;

    // Gemini
    std::vector<ai::GeminiProblem> geminiProblems_;
    std::vector<PendingFix>        pendingFixes_;
    core::SystemDiagnostics        lastDiag_{};
    bool                           deepScanRunning_ = false;
    std::string                    deepScanStatus_  = "Not yet run";

    // Security (from last deep scan)
    std::vector<core::SuspiciousProcess> suspiciousProcs_;
    bool firewallEnabled_ = false;
    core::NetworkStatus networkStatus_{};

    // Log viewer
    static constexpr std::size_t MAX_LOG_LINES = 200;
    std::deque<LogEntry> logLines_;

    // Timing
    std::chrono::steady_clock::time_point lastHeuristic_;
    std::chrono::steady_clock::time_point lastDeep_;

    // (healer/fixer stats queried directly from the objects)
};

} // namespace fikcer::gui

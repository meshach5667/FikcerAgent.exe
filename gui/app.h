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

#include "agent/agent.h"

#include <array>
#include <atomic>
#include <filesystem>
#include <future>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

struct GLFWwindow;   // Forward declaration – no GLFW include in header.

namespace fikcer::gui {

// ── Log ring buffer entry
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
    void drawIssueReporter();
    void drawLogViewer();

    // ── UI helpers ─────────────────────────────────────────────────────────
    void drawHealthGauge(const char* label, float value, float warnAt, float critAt);
    void drawActivityFeed();
    void pushLog(LogEntry::Level lvl, const std::string& msg);
    bool exportLogLines();
    bool exportIssueReport();
    bool writeTextFile(const std::filesystem::path& filePath,
                       const std::string& content);
    std::string currentTimestampSlug() const;

    // ── Window state ───────────────────────────────────────────────────────
    GLFWwindow*        window_ = nullptr;
    std::atomic<bool>  shutdownRequested_{false};

    // ── Agent Backend ──────────────────────────────────────────────────────
    agent::Agent       agent_;

    // ── Shared state (protected by mutex_) ─────────────────────────────────
    mutable std::mutex mutex_;

    // Dashboard
    static constexpr std::size_t MAX_GRAPH_SAMPLES = 120;
    std::deque<float> cpuHistory_;
    std::deque<float> memHistory_;

    // Alerts
    static constexpr std::size_t MAX_ALERTS = 50;
    std::deque<ai::Anomaly> alerts_;

    // Log viewer
    static constexpr std::size_t MAX_LOG_LINES = 200;
    std::deque<LogEntry> logLines_;

    // Issue reporter
    static constexpr std::size_t ISSUE_TITLE_MAX = 128;
    static constexpr std::size_t ISSUE_DETAILS_MAX = 2048;
    std::array<char, ISSUE_TITLE_MAX> issueTitle_{};
    std::array<char, ISSUE_DETAILS_MAX> issueDetails_{};
    int issueCategoryIndex_ = 0;
    std::string issueStatusMessage_;
};

} // namespace fikcer::gui

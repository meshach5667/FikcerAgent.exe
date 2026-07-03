// ============================================================================
// FikcerAgent – Agent Orchestrator Interface
// ============================================================================
// The Agent is the top-level orchestrator that runs the autonomous loop:
//
//   Observe → Analyze → Reason → Plan → Decide → Act → Verify → Learn
//
// It owns all agent subsystems and coordinates them on a background thread.
// The GUI and CLI modes create an Agent instance and observe its state.
// ============================================================================
#pragma once

#include "agent/goal_manager.h"
#include "agent/world_state.h"
#include "agent/memory_store.h"
#include "agent/tool_registry.h"
#include "agent/ai_planner.h"
#include "agent/impact_classifier.h"
#include "agent/reflection_engine.h"
#include "agent/learning_engine.h"
#include "agent/health_score.h"

#include "core/monitor.h"
#include "core/system_scanner.h"
#include "ai/anomaly_detector.h"
#include "ai/gemini_client.h"
#include "actions/process_manager.h"
#include "actions/auto_healer.h"

#include <atomic>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace fikcer::agent {

// ── Pending approval request ───────────────────────────────────────────────

struct ApprovalRequest {
    int              id = 0;
    ActionPlan       plan;
    ImpactAssessment impact;
    bool             approved = false;
    bool             denied   = false;
    bool             executed = false;
    bool             succeeded = false;
    std::string      resultDetails;
};

// ── User-reported issue ───────────────────────────────────────────────────

struct UserIssueReport {
    std::string category;
    std::string title;
    std::string details;
};

// ── Agent event callback ───────────────────────────────────────────────────

struct AgentEvent {
    enum Type { LOG, ALERT, APPROVAL_NEEDED, ACTION_TAKEN, HEALTH_UPDATE };
    Type        type;
    std::string message;
    std::string severity;  ///< "info", "warn", "error", "critical"
};

using AgentEventCallback = std::function<void(const AgentEvent&)>;

// ── Agent ──────────────────────────────────────────────────────────────────

class Agent final {
public:
    Agent();
    ~Agent();

    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    /// Initialize all subsystems.
    /// @return true on success.
    [[nodiscard]] bool init();

    /// Start the agent loop on a background thread.
    bool start();

    /// Stop the agent loop and all subsystems.
    void stop();

    /// @return true if the agent loop is running.
    [[nodiscard]] bool isRunning() const noexcept;

    /// Register an event callback.
    void setEventCallback(AgentEventCallback cb);

    // ── State queries (thread-safe) ────────────────────────────────────────

    /// Get a snapshot of the current world state.
    [[nodiscard]] WorldState worldState() const;

    /// Get the current health score.
    [[nodiscard]] double healthScore() const;

    /// Get detailed health component scores.
    [[nodiscard]] HealthScoreEngine::ComponentScores healthDetails() const;

    /// Get all goals.
    [[nodiscard]] std::vector<Goal> goals() const;

    /// Get unsatisfied goals.
    [[nodiscard]] std::vector<Goal> unsatisfiedGoals() const;

    /// Get pending approval requests.
    [[nodiscard]] std::vector<ApprovalRequest> pendingApprovals() const;

    /// Approve a pending action by ID.
    void approveAction(int id);

    /// Deny a pending action by ID.
    void denyAction(int id);

    /// Get recent action plans (for display).
    [[nodiscard]] std::vector<ActionPlan> recentPlans() const;

    /// Force an immediate deep scan.
    void requestDeepScan();

    /// Record a user-reported issue and queue the agent to investigate it.
    [[nodiscard]] bool submitUserIssue(const std::string& category,
                                       const std::string& title,
                                       const std::string& details);

    // ── Direct subsystem access (for GUI compatibility) ────────────────────

    [[nodiscard]] core::Monitor& monitor() { return monitor_; }
    [[nodiscard]] ai::AnomalyDetector& detector() { return detector_; }
    [[nodiscard]] actions::ProcessManager& processManager() { return procMgr_; }
    [[nodiscard]] actions::AutoHealer& healer() { return healer_; }
    [[nodiscard]] ai::GeminiClient& gemini() { return gemini_; }
    [[nodiscard]] core::SystemScanner& scanner() { return scanner_; }
    [[nodiscard]] MemoryStore& memory() { return memory_; }
    [[nodiscard]] const MemoryStore& memory() const { return memory_; }
    [[nodiscard]] ToolRegistry& toolRegistry() { return tools_; }
    [[nodiscard]] const ToolRegistry& toolRegistry() const { return tools_; }
    [[nodiscard]] bool geminiReady() const { return geminiReady_; }

private:
    // ── Agent loop ─────────────────────────────────────────────────────────
    void agentLoop();
    void agentTick();

    // ── Loop phases ────────────────────────────────────────────────────────
    void observe();     ///< Update WorldState.
    void analyze();     ///< Run heuristic anomaly detection.
    void reason();      ///< Evaluate goals.
    void plan();        ///< AI planning with Gemini.
    void decide();      ///< Impact classification and approval routing.
    void act();         ///< Execute approved actions.
    void verify();      ///< Reflection on outcomes.
    void learn();       ///< Store learnings.

    void emitEvent(AgentEvent::Type type, const std::string& msg,
                   const std::string& sev = "info");

    // ── Subsystems ─────────────────────────────────────────────────────────
    core::Monitor              monitor_;
    actions::ProcessManager    procMgr_;
    ai::AnomalyDetector        detector_;
    actions::AutoHealer        healer_{procMgr_};
    ai::GeminiClient           gemini_;
    core::SystemScanner        scanner_;

    GoalManager                goalMgr_;
    MemoryStore                memory_;
    ToolRegistry               tools_;
    AiPlanner                  planner_;
    ImpactClassifier           classifier_;
    ReflectionEngine           reflection_;
    LearningEngine             learning_;
    HealthScoreEngine          healthEngine_;

    bool geminiReady_ = false;

    // ── Thread ─────────────────────────────────────────────────────────────
    std::thread         agentThread_;
    std::atomic<bool>   running_{false};
    std::atomic<bool>   requestDeepScan_{false};

    // ── Shared state ───────────────────────────────────────────────────────
    mutable std::mutex  mutex_;
    WorldState          worldState_;
    double              currentHealthScore_ = 100.0;
    HealthScoreEngine::ComponentScores healthDetails_{};

    std::vector<ai::Anomaly>   latestAnomalies_;
    std::vector<ActionPlan>    currentPlans_;
    std::deque<ActionPlan>     recentPlans_;
    static constexpr size_t    MAX_RECENT_PLANS = 50;

    std::vector<ApprovalRequest> approvals_;
    int nextApprovalId_ = 1;

    AgentEventCallback eventCallback_;

    // ── Timing ─────────────────────────────────────────────────────────────
    std::chrono::steady_clock::time_point lastDeepScan_;
    std::chrono::steady_clock::time_point lastHeuristic_;

    // ── Diagnostics cache ──────────────────────────────────────────────────
    core::SystemDiagnostics lastDiag_;
    bool                    hasDiag_ = false;
};

} // namespace fikcer::agent

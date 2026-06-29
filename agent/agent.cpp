// ============================================================================
// FikcerAgent – Agent Orchestrator Implementation
// ============================================================================
#include "agent/agent.h"
#include "config.h"
#include "utils/logger.h"
#include "utils/notify.h"

#include <algorithm>
#include <chrono>
#include <filesystem>

namespace fikcer::agent {

using utils::Logger;

namespace {

static std::string joinPreview(const std::vector<ai::Anomaly>& anomalies,
                               std::size_t maxItems = 2) {
    if (anomalies.empty()) {
        return "nothing urgent";
    }

    std::ostringstream oss;
    const std::size_t count = std::min(maxItems, anomalies.size());
    for (std::size_t i = 0; i < count; ++i) {
        if (i) oss << "; ";
        oss << anomalies[i].description;
    }
    if (anomalies.size() > count) {
        oss << "; and " << (anomalies.size() - count) << " more";
    }
    return oss.str();
}

static std::string healActionToText(actions::HealAction action) {
    switch (action) {
        case actions::HealAction::TERMINATE:         return "terminated the process";
        case actions::HealAction::RESTART:           return "restarted the process";
        case actions::HealAction::TERMINATE_RESTART: return "terminated and restarted the process";
        case actions::HealAction::PURGE_CACHE:       return "cleared system caches";
        case actions::HealAction::LOG_ONLY:          return "logged the issue";
        case actions::HealAction::NONE:              return "did not take action";
    }
    return "updated the system";
}

static std::string healthSnapshotText(const WorldState& state) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(0);
    oss << "I refreshed the system snapshot: CPU " << state.cpuPercent
        << "%, memory " << state.memPercent << "%, disk "
        << state.maxDiskPercent << "%.";
    if (!state.activeThreats.empty()) {
        oss << " I can still see " << state.activeThreats.size()
            << " security threat(s).";
    } else {
        oss << " I do not see any active security threats right now.";
    }
    return oss.str();
}

} // namespace

Agent::Agent() = default;

Agent::~Agent() {
    stop();
}

// ── Initialization ─────────────────────────────────────────────────────────

bool Agent::init() {
    auto& logger = Logger::instance();
    if (!logger.init(std::string(config::LOG_DIRECTORY),
                     config::LOG_FILE_PREFIX,
                     config::MAX_LOG_FILE_SIZE,
                     config::MAX_LOG_FILES,
                     utils::LogLevel::INFO)) {
        return false;
    }
    logger.info("Agent v2.0 initializing...");

    // Memory store.
    std::string home;
#ifdef _WIN32
    const char* up = std::getenv("USERPROFILE");
    if (up) home = up;
#else
    const char* h = std::getenv("HOME");
    if (h) home = h;
#endif
    std::string dbPath = home + "/.fikcerAgent/memory.db";
    if (!memory_.open(dbPath)) {
        logger.warn("Agent: memory store failed to open (non-fatal).");
    }

    // Tool registry.
    tools_.registerDefaultTools();

    healer_.setCallback([this](const actions::HealRecord& rec) {
        std::ostringstream msg;
        msg << "Auto-heal " << (rec.success ? "worked" : "needs attention")
            << ": " << healActionToText(rec.action) << " for "
            << rec.processName;
        if (!rec.description.empty()) {
            msg << " — " << rec.description;
        }
        emitEvent(rec.success ? AgentEvent::ACTION_TAKEN : AgentEvent::ALERT,
                  msg.str(),
                  rec.success ? "info" : "warn");
    });

    // Goal manager.
    goalMgr_.initDefaultGoals();

    // Monitor.
    if (!monitor_.start(config::MONITOR_INTERVAL_MS)) {
        logger.error("Agent: monitor failed to start.");
        return false;
    }

    // Process manager.
#ifdef __APPLE__
    procMgr_.addToWhitelist("TextEdit");
    procMgr_.addToWhitelist("Calculator");
    procMgr_.addToWhitelist("Notes");
#elif defined(_WIN32)
    procMgr_.addToWhitelist("notepad.exe");
    procMgr_.addToWhitelist("explorer.exe");
#endif
    procMgr_.start(config::PROCESS_SCAN_INTERVAL_MS);

    // Gemini.
    geminiReady_ = gemini_.init();
    if (geminiReady_) {
        logger.info("Agent: Gemini AI connected (model: " +
                     gemini_.modelName() + ")");
    } else {
        logger.warn("Agent: Gemini AI unavailable — local detection only.");
    }

    emitEvent(AgentEvent::LOG, "FikcerAgent v2.0 initialized.", "info");
    return true;
}

// ── Start / Stop ───────────────────────────────────────────────────────────

bool Agent::start() {
    if (running_) return true;
    running_ = true;
    lastHeuristic_ = std::chrono::steady_clock::now();
    lastDeepScan_ = std::chrono::steady_clock::now() -
        std::chrono::milliseconds(config::DEEP_SCAN_INTERVAL_MS - 10000);
    agentThread_ = std::thread(&Agent::agentLoop, this);
    emitEvent(AgentEvent::LOG, "Agent loop started.", "info");
    return true;
}

void Agent::stop() {
    if (!running_) return;
    running_ = false;
    if (agentThread_.joinable()) agentThread_.join();
    procMgr_.stop();
    monitor_.stop();
    memory_.close();
    Logger::instance().shutdown();
}

bool Agent::isRunning() const noexcept {
    return running_.load();
}

void Agent::setEventCallback(AgentEventCallback cb) {
    std::lock_guard lock(mutex_);
    eventCallback_ = std::move(cb);
}

// ── Agent loop ─────────────────────────────────────────────────────────────

void Agent::agentLoop() {
    Logger::instance().info("Agent: loop thread started.");

    while (running_) {
        agentTick();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    Logger::instance().info("Agent: loop thread stopped.");
}

void Agent::agentTick() {
    auto now = std::chrono::steady_clock::now();

    // Heuristic analysis interval.
    auto hElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - lastHeuristic_).count();
    if (hElapsed >= config::AI_SCAN_INTERVAL_MS) {
        lastHeuristic_ = now;

        observe();
        analyze();
        reason();

        // Execute any previously approved actions.
        act();
    }

    // Deep scan interval (or forced).
    bool forceDeep = requestDeepScan_.exchange(false);
    auto dElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - lastDeepScan_).count();
    if (forceDeep || dElapsed >= config::DEEP_SCAN_INTERVAL_MS) {
        lastDeepScan_ = now;

        // Full deep scan.
        emitEvent(AgentEvent::LOG,
                  "I am running a deeper scan to check health, security, and any blocked actions.",
                  "info");
        auto diag = scanner_.scan();
        {
            std::lock_guard lock(mutex_);
            lastDiag_ = diag;
            hasDiag_ = true;
        }

        // Update world state with fresh diagnostics.
        observe();

        // AI planning (if Gemini available).
        if (geminiReady_) {
            plan();
            decide();
        }

        // Verify & learn from any actions taken.
        verify();
        learn();
    }
}

// ── OBSERVE ────────────────────────────────────────────────────────────────

void Agent::observe() {
    auto stats = monitor_.latestStats();
    auto processes = ai::AnomalyDetector::sampleProcessResources();

    core::SystemDiagnostics diag;
    {
        std::lock_guard lock(mutex_);
        if (hasDiag_) {
            diag = lastDiag_;
        }
    }

    // Compute health score.
    WorldState tempState;
    tempState.update(stats, diag, latestAnomalies_, processes, 100.0);
    double health = healthEngine_.compute(tempState, memory_);
    auto details = healthEngine_.computeDetailed(tempState, memory_);

    // Build final world state.
    {
        std::lock_guard lock(mutex_);
        worldState_.update(stats, diag, latestAnomalies_, processes, health);
        currentHealthScore_ = health;
        healthDetails_ = details;
        stateCopy = worldState_;
    }

    emitEvent(AgentEvent::LOG, healthSnapshotText(stateCopy), "info");
}

// ── ANALYZE ────────────────────────────────────────────────────────────────

void Agent::analyze() {
    auto stats = monitor_.latestStats();
    auto processes = ai::AnomalyDetector::sampleProcessResources();
    auto anomalies = detector_.feed(stats, processes);

    if (!anomalies.empty()) {
        {
            std::lock_guard lock(mutex_);
            latestAnomalies_ = anomalies;
        }

        emitEvent(AgentEvent::ALERT,
                  "I found " + std::to_string(anomalies.size()) +
                  " live issue(s): " + joinPreview(anomalies) + ".",
                  "warn");

        // Auto-heal heuristic anomalies.
        healer_.handleAnomalies(anomalies);
    } else {
        emitEvent(AgentEvent::LOG,
                  "I did not find any new live performance problems in this pass.",
                  "info");
    }
}

// ── REASON ─────────────────────────────────────────────────────────────────

void Agent::reason() {
    WorldState state;
    {
        std::lock_guard lock(mutex_);
        state = worldState_;
    }
    goalMgr_.evaluate(state);

    emitEvent(AgentEvent::LOG,
              "I compared the current system state against the active goals.",
              "info");
}

// ── PLAN ───────────────────────────────────────────────────────────────────

void Agent::plan() {
    WorldState state;
    {
        std::lock_guard lock(mutex_);
        state = worldState_;
    }

    auto unsatisfied = goalMgr_.unsatisfiedGoals();

    auto plans = planner_.plan(gemini_, state, unsatisfied, memory_, tools_);

    {
        std::lock_guard lock(mutex_);
        currentPlans_ = plans;
        for (const auto& p : plans) {
            recentPlans_.push_back(p);
            while (recentPlans_.size() > MAX_RECENT_PLANS)
                recentPlans_.pop_front();
        }
    }

    if (plans.empty()) {
        emitEvent(AgentEvent::LOG,
                  "The AI did not find any fixes that need action right now.",
                  "info");
    } else {
        emitEvent(AgentEvent::ALERT,
                  "The AI prepared " + std::to_string(plans.size()) +
                  " fix plan(s) and I will check them against the allowed tools.",
                  "warn");
    }
}

// ── DECIDE ─────────────────────────────────────────────────────────────────

void Agent::decide() {
    std::vector<ActionPlan> plans;
    {
        std::lock_guard lock(mutex_);
        plans = currentPlans_;
    }

    for (const auto& p : plans) {
        auto impact = classifier_.classify(p, tools_, memory_);

        switch (impact.approval) {
            case ApprovalRequirement::AUTO_EXECUTE: {
                // Capture before state.
                WorldState beforeState;
                {
                    std::lock_guard lock(mutex_);
                    beforeState = worldState_;
                }
                reflection_.captureBeforeState(beforeState);

                // Execute immediately.
                auto result = tools_.execute(p.recommendedAction, p.parameters);
                emitEvent(AgentEvent::ACTION_TAKEN,
                          std::string("I ran the low-risk fix automatically: ") +
                          p.recommendedAction +
                          (result.success ? " and it worked." : " and it failed."),
                          result.success ? "info" : "warn");

                // Reflect.
                observe();  // Refresh state.
                WorldState afterState;
                {
                    std::lock_guard lock(mutex_);
                    afterState = worldState_;
                }
                auto ref = reflection_.evaluate(p, result, afterState);
                reflection_.recordToMemory(ref, p, memory_);
                break;
            }

            case ApprovalRequirement::NOTIFY_USER: {
                // Auto-execute but notify.
                WorldState beforeState;
                {
                    std::lock_guard lock(mutex_);
                    beforeState = worldState_;
                }
                reflection_.captureBeforeState(beforeState);

                auto result = tools_.execute(p.recommendedAction, p.parameters);

                emitEvent(AgentEvent::ACTION_TAKEN,
                          "I ran a fix that may affect the session: " +
                          p.recommendedAction + ". " + impact.impactDescription,
                          "warn");

                if constexpr (config::NOTIFICATIONS_ENABLED) {
                    utils::sendNotification("FikcerAgent",
                        p.recommendedAction + ": " + p.reasoning,
                        impact.impactDescription);
                }

                observe();
                WorldState afterState;
                {
                    std::lock_guard lock(mutex_);
                    afterState = worldState_;
                }
                auto ref = reflection_.evaluate(p, result, afterState);
                reflection_.recordToMemory(ref, p, memory_);
                break;
            }

            case ApprovalRequirement::WAIT_APPROVAL: {
                // Queue for user approval.
                std::lock_guard lock(mutex_);
                ApprovalRequest req;
                req.id = nextApprovalId_++;
                req.plan = p;
                req.impact = impact;
                approvals_.push_back(std::move(req));

                emitEvent(AgentEvent::APPROVAL_NEEDED,
                          "I found a higher-risk fix and need your approval before I continue: " +
                          p.recommendedAction + ". " + impact.impactDescription,
                          "warn");
                break;
            }

            case ApprovalRequirement::BLOCKED: {
                emitEvent(AgentEvent::LOG,
                          "I skipped " + p.recommendedAction +
                          " because your preferences block it.",
                          "info");
                break;
            }
        }
    }
}

// ── ACT ────────────────────────────────────────────────────────────────────

void Agent::act() {
    std::vector<ApprovalRequest> toExecute;

    {
        std::lock_guard lock(mutex_);
        for (auto& req : approvals_) {
            if (req.approved && !req.executed) {
                req.executed = true;
                toExecute.push_back(req);
            }
        }
        // Remove old denied/executed requests.
        approvals_.erase(
            std::remove_if(approvals_.begin(), approvals_.end(),
                           [](const ApprovalRequest& r) {
                               return r.denied || (r.executed && r.succeeded);
                           }),
            approvals_.end());
    }

    for (auto& req : toExecute) {
        // Capture before state.
        WorldState beforeState;
        {
            std::lock_guard lock(mutex_);
            beforeState = worldState_;
        }
        reflection_.captureBeforeState(beforeState);

        auto result = tools_.execute(
            req.plan.recommendedAction, req.plan.parameters);

        req.succeeded = result.success;
        req.resultDetails = result.success ? result.output : result.error;

        emitEvent(AgentEvent::ACTION_TAKEN,
                  "I ran your approved fix: " + req.plan.recommendedAction +
                  (result.success ? " and it succeeded." : " and it failed."),
                  result.success ? "info" : "warn");

        // Reflect & learn.
        observe();
        WorldState afterState;
        {
            std::lock_guard lock(mutex_);
            afterState = worldState_;
        }
        auto ref = reflection_.evaluate(req.plan, result, afterState);
        reflection_.recordToMemory(ref, req.plan, memory_);

        // Update approval status.
        {
            std::lock_guard lock(mutex_);
            for (auto& a : approvals_) {
                if (a.id == req.id) {
                    a.succeeded = req.succeeded;
                    a.resultDetails = req.resultDetails;
                }
            }
        }
    }
}

// ── VERIFY ─────────────────────────────────────────────────────────────────

void Agent::verify() {
    // Re-observe to get latest state.
    observe();

    WorldState state;
    double health;
    {
        std::lock_guard lock(mutex_);
        state = worldState_;
        health = currentHealthScore_;
    }

    // Re-evaluate goals.
    goalMgr_.evaluate(state);

    emitEvent(AgentEvent::HEALTH_UPDATE,
              "After re-checking, the system health is " +
              std::to_string(static_cast<int>(health)) + "/100 (" +
              std::string(healthTierTag(HealthScoreEngine::tier(health))) + ")",
              health >= 90.0 ? "info" : (health >= 70.0 ? "warn" : "error"));
}

// ── LEARN ──────────────────────────────────────────────────────────────────

void Agent::learn() {
    // Learning is done incrementally in the reflect step.
    // This phase just logs the overall learning state.
    double overallRate = learning_.overallSuccessRate(memory_);
    std::ostringstream msg;
    msg << "I recorded the latest outcome. My overall action success rate is "
        << static_cast<int>(overallRate * 100) << "%."];
    emitEvent(AgentEvent::LOG, msg.str(), "info");
}

// ── State queries ──────────────────────────────────────────────────────────

WorldState Agent::worldState() const {
    std::lock_guard lock(mutex_);
    return worldState_;
}

double Agent::healthScore() const {
    std::lock_guard lock(mutex_);
    return currentHealthScore_;
}

HealthScoreEngine::ComponentScores Agent::healthDetails() const {
    std::lock_guard lock(mutex_);
    return healthDetails_;
}

std::vector<Goal> Agent::goals() const {
    return goalMgr_.goals();
}

std::vector<Goal> Agent::unsatisfiedGoals() const {
    return goalMgr_.unsatisfiedGoals();
}

std::vector<ApprovalRequest> Agent::pendingApprovals() const {
    std::lock_guard lock(mutex_);
    std::vector<ApprovalRequest> result;
    for (const auto& a : approvals_) {
        if (!a.approved && !a.denied) result.push_back(a);
    }
    return result;
}

void Agent::approveAction(int id) {
    std::lock_guard lock(mutex_);
    for (auto& a : approvals_) {
        if (a.id == id) { a.approved = true; break; }
    }
}

void Agent::denyAction(int id) {
    std::lock_guard lock(mutex_);
    for (auto& a : approvals_) {
        if (a.id == id) { a.denied = true; break; }
    }
}

std::vector<ActionPlan> Agent::recentPlans() const {
    std::lock_guard lock(mutex_);
    return {recentPlans_.begin(), recentPlans_.end()};
}

void Agent::requestDeepScan() {
    requestDeepScan_ = true;
}

// ── Event emission ─────────────────────────────────────────────────────────

void Agent::emitEvent(AgentEvent::Type type, const std::string& msg,
                       const std::string& sev) {
    // Log all events.
    if (sev == "error" || sev == "critical")
        Logger::instance().error(msg);
    else if (sev == "warn")
        Logger::instance().warn(msg);
    else
        Logger::instance().info(msg);

    // Fire callback.
    AgentEventCallback cb;
    {
        std::lock_guard lock(mutex_);
        cb = eventCallback_;
    }
    if (cb) {
        try { cb({type, msg, sev}); }
        catch (...) {}
    }
}

} // namespace fikcer::agent

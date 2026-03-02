// ============================================================================
// FikcerAgent – Auto-Healer Interface
// ============================================================================
// The AutoHealer consumes Anomaly events from the AI detector and takes
// corrective action:
//
//   • Terminate resource-hogging processes (if whitelisted)
//   • Restart terminated processes
//   • Trigger memory pressure relief (purge caches on macOS)
//   • Log all actions with full audit trail
//
// All actions respect the whitelist and DRY_RUN safety flag.
// ============================================================================
#pragma once

#include "ai/anomaly_detector.h"
#include "actions/process_manager.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace fikcer::actions {

// ── Heal action record ─────────────────────────────────────────────────────

enum class HealAction : uint8_t {
    NONE             = 0,
    TERMINATE        = 1,   ///< Killed a process
    RESTART          = 2,   ///< Restarted a process
    TERMINATE_RESTART= 3,   ///< Killed then restarted
    PURGE_CACHE      = 4,   ///< Triggered OS memory cache purge
    LOG_ONLY         = 5,   ///< Logged but took no action (not whitelisted / dry-run)
};

struct HealRecord {
    HealAction        action = HealAction::NONE;
    ai::AnomalyType   cause  = ai::AnomalyType::NONE;
    ai::Severity       severity = ai::Severity::LOW;
    uint32_t           pid    = 0;
    std::string        processName;
    std::string        description;
    bool               success = false;
    std::chrono::steady_clock::time_point timestamp;
};

/// Callback fired after each heal attempt.
using HealCallback = std::function<void(const HealRecord&)>;

// ── AutoHealer ─────────────────────────────────────────────────────────────

class AutoHealer final {
public:
    /// Construct with a reference to the process manager (for whitelist access).
    explicit AutoHealer(ProcessManager& procMgr);
    ~AutoHealer() = default;

    AutoHealer(const AutoHealer&) = delete;
    AutoHealer& operator=(const AutoHealer&) = delete;

    /// Register a callback for heal events.
    void setCallback(HealCallback cb);

    /// Process a batch of anomalies and take corrective action.
    /// Returns a list of all actions taken.
    std::vector<HealRecord> handleAnomalies(
        const std::vector<ai::Anomaly>& anomalies);

    /// Get statistics.
    [[nodiscard]] uint64_t totalTerminations() const noexcept;
    [[nodiscard]] uint64_t totalRestarts()     const noexcept;
    [[nodiscard]] uint64_t totalPurgeCaches()  const noexcept;

private:
    // ── Per-anomaly handlers ───────────────────────────────────────────────
    HealRecord handleProcessCpuHog(const ai::Anomaly& a);
    HealRecord handleProcessMemHog(const ai::Anomaly& a);
    HealRecord handleMemorySpike(const ai::Anomaly& a);
    HealRecord handleSystemOverload(const ai::Anomaly& a);
    HealRecord logOnly(const ai::Anomaly& a);

    /// Try to purge OS caches to reclaim memory.
    bool purgeSystemCaches();

    // ── State ──────────────────────────────────────────────────────────────
    ProcessManager& procMgr_;
    HealCallback    callback_;
    mutable std::mutex mutex_;

    std::atomic<uint64_t> totalTerminations_{0};
    std::atomic<uint64_t> totalRestarts_{0};
    std::atomic<uint64_t> totalPurgeCaches_{0};

    // Track per-PID heal history to avoid hammering the same process.
    struct PidHealHistory {
        unsigned int healAttempts = 0;
        std::chrono::steady_clock::time_point lastAttempt;
    };
    std::unordered_map<uint32_t, PidHealHistory> pidHistory_;
};

} // namespace fikcer::actions

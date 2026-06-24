// ============================================================================
// FikcerAgent – Learning Engine Interface
// ============================================================================
// Queries MemoryStore to build action effectiveness profiles and provides
// recommendations to the AI Planner for future decisions.
// ============================================================================
#pragma once

#include "agent/memory_store.h"

#include <string>
#include <vector>

namespace fikcer::agent {

// ── Action effectiveness profile ───────────────────────────────────────────

struct ActionProfile {
    std::string actionName;
    double      successRate = 0.0;      ///< 0.0 - 1.0
    int         totalAttempts = 0;
    double      avgHealthImprovement = 0.0;
};

// ── Learning Engine ────────────────────────────────────────────────────────

class LearningEngine final {
public:
    LearningEngine() = default;
    ~LearningEngine() = default;

    /// Get the best actions for a given problem type, ranked by success.
    [[nodiscard]] std::vector<ActionProfile> getBestActions(
        const MemoryStore& memory,
        const std::string& problemType) const;

    /// Check if an action should be avoided (low success rate).
    [[nodiscard]] bool shouldAvoidAction(
        const MemoryStore& memory,
        const std::string& actionName,
        int minSamples = 5) const;

    /// Build formatted learning context for the AI planner prompt.
    [[nodiscard]] std::string getContextForPlanner(
        const MemoryStore& memory) const;

    /// Get the overall success rate across all actions.
    [[nodiscard]] double overallSuccessRate(
        const MemoryStore& memory) const;
};

} // namespace fikcer::agent

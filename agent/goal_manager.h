// ============================================================================
// FikcerAgent – Goal Manager Interface
// ============================================================================
// Maintains a prioritized list of system health goals and evaluates them
// against the current world state each agent cycle.
//
// Goals are dynamically re-prioritized based on how far they are from
// their target values (urgency) and their base priority level.
// ============================================================================
#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace fikcer::agent {

// Forward declaration
struct WorldState;

// ── Goal priority levels ───────────────────────────────────────────────────

enum class GoalPriority : uint8_t {
    LOW      = 0,
    MEDIUM   = 1,
    HIGH     = 2,
    CRITICAL = 3,
};

[[nodiscard]] constexpr std::string_view goalPriorityTag(GoalPriority p) noexcept {
    switch (p) {
        case GoalPriority::LOW:      return "LOW";
        case GoalPriority::MEDIUM:   return "MEDIUM";
        case GoalPriority::HIGH:     return "HIGH";
        case GoalPriority::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

// ── Goal definition ────────────────────────────────────────────────────────

struct Goal {
    std::string  name;              ///< Human-readable goal name.
    std::string  category;          ///< "health", "security", "performance", "stability"
    GoalPriority basePriority;      ///< Configured priority level.
    GoalPriority effectivePriority; ///< Dynamic priority (may escalate if far from target).
    bool         satisfied = false; ///< True if current value meets the target.
    double       currentValue = 0.0;///< Current measured value.
    double       targetValue  = 0.0;///< Required value for satisfaction.
    bool         isBoolean = false; ///< If true, target is 1.0 (on) or 0.0 (off).
    std::string  description;       ///< Explanation shown to user / AI.

    /// Urgency score (higher = more urgent).  Used for dynamic prioritization.
    [[nodiscard]] double urgency() const noexcept;
};

// ── Goal evaluation callback ───────────────────────────────────────────────

/// Function that reads a value from the WorldState for a specific goal.
using GoalEvaluator = std::function<double(const WorldState&)>;

// ── GoalManager ────────────────────────────────────────────────────────────

class GoalManager final {
public:
    GoalManager();
    ~GoalManager() = default;

    GoalManager(const GoalManager&) = delete;
    GoalManager& operator=(const GoalManager&) = delete;

    /// Register the default system goals.
    void initDefaultGoals();

    /// Add a custom goal with its evaluator function.
    void addGoal(Goal goal, GoalEvaluator evaluator);

    /// Evaluate all goals against the current world state.
    /// Updates `satisfied`, `currentValue`, and `effectivePriority` for each goal.
    void evaluate(const WorldState& state);

    /// @return All goals, sorted by effective priority (most urgent first).
    [[nodiscard]] std::vector<Goal> goals() const;

    /// @return Only unsatisfied goals, sorted by urgency.
    [[nodiscard]] std::vector<Goal> unsatisfiedGoals() const;

    /// @return True if all goals are satisfied.
    [[nodiscard]] bool allSatisfied() const;

    /// @return A formatted string summary for the AI planner.
    [[nodiscard]] std::string summaryForPlanner() const;

private:
    /// Recalculate effective priorities based on current values.
    void reprioritize();

    /// Internal goal addition (no lock).
    void addGoalInternal(Goal goal, GoalEvaluator evaluator);

    struct GoalEntry {
        Goal          goal;
        GoalEvaluator evaluator;
    };

    mutable std::mutex mutex_;
    std::vector<GoalEntry> entries_;
};

} // namespace fikcer::agent

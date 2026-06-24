// ============================================================================
// FikcerAgent – Reflection Engine Interface
// ============================================================================
// After every action, the Reflection Engine evaluates outcomes by comparing
// the "before" and "after" world states.  Results are stored in MemoryStore
// to feed the Learning Engine.
// ============================================================================
#pragma once

#include "agent/world_state.h"
#include "agent/memory_store.h"
#include "agent/ai_planner.h"
#include "agent/tool_registry.h"

#include <string>

namespace fikcer::agent {

// ── Reflection result ──────────────────────────────────────────────────────

struct ReflectionResult {
    std::string actionName;
    std::string issue;
    double      healthBefore = 0.0;
    double      healthAfter  = 0.0;
    double      targetMetricBefore = 0.0;
    double      targetMetricAfter  = 0.0;
    bool        issueResolved   = false;
    bool        healthImproved  = false;
    bool        regressionDetected = false;
    std::string outcome;        ///< "success", "partial", "failure", "regression"
    std::string details;
};

// ── Reflection Engine ──────────────────────────────────────────────────────

class ReflectionEngine final {
public:
    ReflectionEngine() = default;
    ~ReflectionEngine() = default;

    /// Capture a "before" snapshot for later comparison.
    void captureBeforeState(const WorldState& state);

    /// Evaluate the result of an action by comparing before/after states.
    [[nodiscard]] ReflectionResult evaluate(
        const ActionPlan& plan,
        const ToolResult& toolResult,
        const WorldState& afterState);

    /// Record the reflection result into persistent memory.
    void recordToMemory(const ReflectionResult& result,
                        const ActionPlan& plan,
                        MemoryStore& memory);

private:
    /// Extract the specific metric targeted by a plan.
    [[nodiscard]] static double extractTargetMetric(
        const WorldState& state, const std::string& issue);

    WorldState beforeState_;
    bool hasBeforeState_ = false;
};

} // namespace fikcer::agent

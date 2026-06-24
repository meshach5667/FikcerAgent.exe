// ============================================================================
// FikcerAgent – AI Planning Engine Interface
// ============================================================================
// The AI planner is the reasoning brain of the agent.  It:
//
//   1. Builds a rich context (WorldState + Memory + Goals + Tools)
//   2. Sends a structured prompt to Gemini requesting JSON output
//   3. Parses the structured plan
//   4. Validates the recommended tool exists
//   5. Returns an ActionPlan for the executor
//
// The AI planner ONLY recommends actions — it never executes them directly.
// ============================================================================
#pragma once

#include "agent/goal_manager.h"
#include "agent/memory_store.h"
#include "agent/tool_registry.h"
#include "agent/world_state.h"
#include "ai/gemini_client.h"

#include <mutex>
#include <string>
#include <vector>

namespace fikcer::agent {

// ── Action Plan ────────────────────────────────────────────────────────────

struct ActionPlan {
    std::string issue;              ///< Identified issue (e.g., "high_cpu_usage").
    std::string rootCause;          ///< Root cause analysis.
    std::string severity;           ///< "low", "medium", "high", "critical".
    std::string recommendedAction;  ///< Tool name from ToolRegistry.
    ToolParams  parameters;         ///< Parameters for the tool.
    double      confidence = 0.0;   ///< AI confidence (0.0 - 1.0).
    std::string riskLevel;          ///< "low", "medium", "high".
    bool        requiresApproval = true;
    std::string reasoning;          ///< AI's explanation of the decision.
    bool        valid = false;      ///< True if plan was successfully parsed.
};

// ── AI Planner ─────────────────────────────────────────────────────────────

class AiPlanner final {
public:
    AiPlanner();
    ~AiPlanner() = default;

    AiPlanner(const AiPlanner&) = delete;
    AiPlanner& operator=(const AiPlanner&) = delete;

    /// Generate action plans for the current system state.
    /// @return Zero or more plans, sorted by severity.
    [[nodiscard]] std::vector<ActionPlan> plan(
        ai::GeminiClient& gemini,
        const WorldState& state,
        const std::vector<Goal>& unsatisfiedGoals,
        const MemoryStore& memory,
        const ToolRegistry& tools);

    /// Parse a single plan from a JSON string.
    /// @return An ActionPlan (valid=false if parsing failed).
    [[nodiscard]] static ActionPlan parsePlan(const std::string& json);

    /// Parse multiple plans from a JSON array string.
    [[nodiscard]] static std::vector<ActionPlan> parsePlans(const std::string& json);

    /// @return The last prompt sent to Gemini (for debugging).
    [[nodiscard]] std::string lastPrompt() const;

    /// @return The last raw response from Gemini.
    [[nodiscard]] std::string lastResponse() const;

private:
    /// Build the full context prompt for Gemini.
    [[nodiscard]] std::string buildPrompt(
        const WorldState& state,
        const std::vector<Goal>& unsatisfiedGoals,
        const MemoryStore& memory,
        const ToolRegistry& tools) const;

    /// Validate that a plan references a real tool.
    bool validatePlan(ActionPlan& plan, const ToolRegistry& tools) const;

    mutable std::mutex mutex_;
    std::string lastPrompt_;
    std::string lastResponse_;
};

} // namespace fikcer::agent

// ============================================================================
// FikcerAgent – Impact Classifier Interface
// ============================================================================
// Classifies agent actions by user impact and determines approval requirements:
//
//   LOW    – Auto-execute (FlushDNS, EnableFirewall, CleanTempFiles)
//   MEDIUM – Notify user, optionally wait (Restart Chrome, Close App)
//   HIGH   – Require explicit approval (Restart PC, Quarantine Files)
//
// Integrates with user preferences from MemoryStore.
// ============================================================================
#pragma once

#include "agent/memory_store.h"
#include "agent/tool_registry.h"
#include "agent/ai_planner.h"

#include <string>

namespace fikcer::agent {

// ── Impact assessment result ───────────────────────────────────────────────

enum class ApprovalRequirement : uint8_t {
    AUTO_EXECUTE = 0,   ///< Execute immediately, no notification.
    NOTIFY_USER  = 1,   ///< Execute but notify user of the action.
    WAIT_APPROVAL = 2,  ///< Require user approval before execution.
    BLOCKED      = 3,   ///< User preference blocks this action entirely.
};

struct ImpactAssessment {
    ApprovalRequirement approval = ApprovalRequirement::WAIT_APPROVAL;
    RiskLevel           risk     = RiskLevel::MEDIUM;
    std::string         impactDescription;  ///< What the user will experience.
    std::string         blockReason;        ///< If blocked, why.
    bool                userPreferenceApplied = false;
};

// ── Impact Classifier ──────────────────────────────────────────────────────

class ImpactClassifier final {
public:
    ImpactClassifier() = default;
    ~ImpactClassifier() = default;

    /// Classify a proposed action plan.
    [[nodiscard]] ImpactAssessment classify(
        const ActionPlan& plan,
        const ToolRegistry& tools,
        const MemoryStore& memory) const;

    /// Get a user-friendly impact description for a tool + parameters.
    [[nodiscard]] static std::string describeImpact(
        const std::string& toolName,
        const ToolParams& params);

    /// Check if a user preference blocks this action.
    [[nodiscard]] static bool isBlockedByPreference(
        const std::string& actionName,
        const ToolParams& params,
        const MemoryStore& memory);
};

} // namespace fikcer::agent

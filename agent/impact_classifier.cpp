// ============================================================================
// FikcerAgent – Impact Classifier Implementation
// ============================================================================
#include "agent/impact_classifier.h"
#include "utils/logger.h"

#include <algorithm>

namespace fikcer::agent {

using utils::Logger;

// ── Classify an action plan ────────────────────────────────────────────────

ImpactAssessment ImpactClassifier::classify(
    const ActionPlan& plan,
    const ToolRegistry& tools,
    const MemoryStore& memory) const
{
    ImpactAssessment result;

    // 1. Check user preferences first (they override everything).
    if (isBlockedByPreference(plan.recommendedAction, plan.parameters, memory)) {
        result.approval = ApprovalRequirement::BLOCKED;
        result.risk = RiskLevel::HIGH;
        result.blockReason = "Blocked by user preference.";
        result.userPreferenceApplied = true;
        Logger::instance().info("ImpactClassifier: " +
                                 plan.recommendedAction + " BLOCKED by preference.");
        return result;
    }

    // 2. Get tool risk level.
    const Tool* tool = tools.findTool(plan.recommendedAction);
    if (!tool) {
        result.approval = ApprovalRequirement::BLOCKED;
        result.risk = RiskLevel::HIGH;
        result.blockReason = "Unknown tool: " + plan.recommendedAction;
        return result;
    }

    result.risk = tool->risk;

    // 3. Classify by risk level.
    switch (tool->risk) {
        case RiskLevel::LOW:
            result.approval = ApprovalRequirement::AUTO_EXECUTE;
            result.impactDescription = "This action is safe and non-disruptive.";
            break;

        case RiskLevel::MEDIUM:
            result.approval = ApprovalRequirement::NOTIFY_USER;
            result.impactDescription = describeImpact(
                plan.recommendedAction, plan.parameters);
            break;

        case RiskLevel::HIGH:
            result.approval = ApprovalRequirement::WAIT_APPROVAL;
            result.impactDescription = describeImpact(
                plan.recommendedAction, plan.parameters);
            break;
    }

    // 4. AI-suggested approval override: if AI says approval needed, escalate.
    if (plan.requiresApproval &&
        result.approval == ApprovalRequirement::AUTO_EXECUTE) {
        result.approval = ApprovalRequirement::NOTIFY_USER;
    }

    // 5. Severity-based escalation: critical severity always requires approval.
    if (plan.severity == "critical" &&
        result.approval != ApprovalRequirement::BLOCKED) {
        result.approval = ApprovalRequirement::WAIT_APPROVAL;
    }

    return result;
}

// ── Impact description ─────────────────────────────────────────────────────

std::string ImpactClassifier::describeImpact(
    const std::string& toolName,
    const ToolParams& params)
{
    if (toolName == "RestartProcess") {
        auto it = params.find("process");
        std::string proc = (it != params.end()) ? it->second : "the application";
        return "\"" + proc + "\" will be terminated. Unsaved work may be lost "
               "and open tabs/windows will close.";
    }

    if (toolName == "ResetNetworkAdapter") {
        return "Your internet connection will drop briefly (2-5 seconds) "
               "while the network adapter is reset.";
    }

    if (toolName == "RestartService") {
        auto it = params.find("service");
        std::string svc = (it != params.end()) ? it->second : "the service";
        return "Service \"" + svc + "\" will restart. Applications depending "
               "on it may be temporarily affected.";
    }

    if (toolName == "QuarantineFile") {
        auto it = params.find("file");
        std::string file = (it != params.end()) ? it->second : "the file";
        return "\"" + file + "\" will be moved to quarantine. If it's a "
               "critical file, the associated application may stop working.";
    }

    if (toolName == "BlockIP") {
        auto it = params.find("ip");
        std::string ip = (it != params.end()) ? it->second : "the IP address";
        return "All connections to/from " + ip + " will be blocked. "
               "This may affect applications using that server.";
    }

    if (toolName == "DisableSuspiciousStartup") {
        return "A startup item will be disabled. It won't run on next login.";
    }

    if (toolName == "RestoreFirewallRules") {
        return "Firewall rules will be reset to secure defaults. Custom rules "
               "you've added will be removed.";
    }

    if (toolName == "CleanTempFiles") {
        return "Temporary and cache files will be deleted to free disk space. "
               "Some applications may need to rebuild their caches.";
    }

    if (toolName == "FlushDNS") {
        return "DNS cache will be cleared. Website lookups may be briefly slower.";
    }

    if (toolName == "EnableFirewall") {
        return "The system firewall will be enabled for protection.";
    }

    return "This action may affect your system. Review before proceeding.";
}

// ── User preference check ──────────────────────────────────────────────────

bool ImpactClassifier::isBlockedByPreference(
    const std::string& actionName,
    const ToolParams& params,
    const MemoryStore& memory)
{
    auto prefs = memory.getAllUserPreferences();

    for (const auto& pref : prefs) {
        if (!pref.enabled) continue;

        // "never_restart:<app>" blocks RestartProcess for that app.
        if (pref.key == "never_restart" && actionName == "RestartProcess") {
            auto it = params.find("process");
            if (it != params.end()) {
                std::string procLower = it->second;
                std::string prefLower = pref.value;
                std::transform(procLower.begin(), procLower.end(),
                               procLower.begin(), ::tolower);
                std::transform(prefLower.begin(), prefLower.end(),
                               prefLower.begin(), ::tolower);
                if (procLower.find(prefLower) != std::string::npos) {
                    return true;
                }
            }
        }

        // "never_kill:<app>" blocks any process termination.
        if (pref.key == "never_kill" && actionName == "RestartProcess") {
            auto it = params.find("process");
            if (it != params.end()) {
                std::string procLower = it->second;
                std::string prefLower = pref.value;
                std::transform(procLower.begin(), procLower.end(),
                               procLower.begin(), ::tolower);
                std::transform(prefLower.begin(), prefLower.end(),
                               prefLower.begin(), ::tolower);
                if (procLower.find(prefLower) != std::string::npos) {
                    return true;
                }
            }
        }

        // "never_quarantine:<path>" blocks quarantine for specific files.
        if (pref.key == "never_quarantine" && actionName == "QuarantineFile") {
            auto it = params.find("file");
            if (it != params.end() &&
                it->second.find(pref.value) != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}

} // namespace fikcer::agent

// ============================================================================
// FikcerAgent – Reflection Engine Implementation
// ============================================================================
#include "agent/reflection_engine.h"
#include "utils/logger.h"

#include <algorithm>
#include <cmath>

namespace fikcer::agent {

using utils::Logger;

void ReflectionEngine::captureBeforeState(const WorldState& state) {
    beforeState_ = state;
    hasBeforeState_ = true;
}

ReflectionResult ReflectionEngine::evaluate(
    const ActionPlan& plan,
    const ToolResult& toolResult,
    const WorldState& afterState)
{
    ReflectionResult result;
    result.actionName = plan.recommendedAction;
    result.issue = plan.issue;

    if (!hasBeforeState_) {
        // No before state — can only check tool result.
        result.healthBefore = afterState.healthScore;
        result.healthAfter  = afterState.healthScore;
        result.outcome = toolResult.success ? "success" : "failure";
        result.details = "No before-state snapshot available.";
        return result;
    }

    result.healthBefore = beforeState_.healthScore;
    result.healthAfter  = afterState.healthScore;
    result.healthImproved = (afterState.healthScore > beforeState_.healthScore);

    // Extract the specific metric this action targeted.
    result.targetMetricBefore = extractTargetMetric(beforeState_, plan.issue);
    result.targetMetricAfter  = extractTargetMetric(afterState, plan.issue);

    // Determine if the issue was resolved.
    if (plan.issue.find("cpu") != std::string::npos ||
        plan.issue.find("CPU") != std::string::npos) {
        result.issueResolved = (afterState.cpuPercent < 85.0);
    } else if (plan.issue.find("mem") != std::string::npos ||
               plan.issue.find("MEM") != std::string::npos) {
        result.issueResolved = (afterState.memPercent < 85.0);
    } else if (plan.issue.find("dns") != std::string::npos ||
               plan.issue.find("DNS") != std::string::npos) {
        result.issueResolved = afterState.dnsWorking;
    } else if (plan.issue.find("firewall") != std::string::npos) {
        result.issueResolved = afterState.firewallEnabled;
    } else if (plan.issue.find("threat") != std::string::npos ||
               plan.issue.find("malware") != std::string::npos) {
        result.issueResolved = afterState.activeThreats.empty();
    } else if (plan.issue.find("network") != std::string::npos ||
               plan.issue.find("internet") != std::string::npos) {
        result.issueResolved = afterState.internetReachable;
    } else {
        // Generic: check if health improved and tool succeeded.
        result.issueResolved = toolResult.success && result.healthImproved;
    }

    // Check for regression (health dropped significantly).
    result.regressionDetected =
        (afterState.healthScore < beforeState_.healthScore - 5.0);

    // Determine outcome.
    if (result.regressionDetected) {
        result.outcome = "regression";
        result.details = "Health score dropped by " +
            std::to_string(static_cast<int>(beforeState_.healthScore - afterState.healthScore)) +
            " points after action.";
    } else if (result.issueResolved && toolResult.success) {
        result.outcome = "success";
        result.details = "Issue resolved. Health: " +
            std::to_string(static_cast<int>(result.healthBefore)) + " → " +
            std::to_string(static_cast<int>(result.healthAfter));
    } else if (toolResult.success && !result.issueResolved) {
        result.outcome = "partial";
        result.details = "Action succeeded but issue not fully resolved.";
    } else {
        result.outcome = "failure";
        result.details = toolResult.error.empty()
            ? "Action did not resolve the issue."
            : toolResult.error;
    }

    Logger::instance().info("Reflection: " + result.actionName + " → " +
                            result.outcome + " (" + result.details + ")");

    hasBeforeState_ = false;
    return result;
}

void ReflectionEngine::recordToMemory(
    const ReflectionResult& result,
    const ActionPlan& plan,
    MemoryStore& memory)
{
    // Record incident.
    IncidentRecord inc;
    inc.problem      = plan.issue;
    inc.rootCause    = plan.rootCause;
    inc.actionTaken  = plan.recommendedAction;
    inc.result       = result.outcome;
    inc.severity     = plan.severity;
    inc.healthBefore = result.healthBefore;
    inc.healthAfter  = result.healthAfter;
    memory.recordIncident(inc);

    // Update action statistics.
    bool success = (result.outcome == "success" || result.outcome == "partial");
    memory.updateActionStats(plan.recommendedAction, success);

    // Record security event if it was a security action.
    if (plan.issue.find("threat") != std::string::npos ||
        plan.issue.find("malware") != std::string::npos ||
        plan.issue.find("firewall") != std::string::npos ||
        plan.issue.find("security") != std::string::npos) {
        SecurityEvent ev;
        ev.type = "response";
        ev.details = plan.issue + " — " + plan.rootCause;
        ev.actionTaken = plan.recommendedAction;
        ev.outcome = result.outcome;
        ev.severity = plan.severity;
        memory.recordSecurityEvent(ev);
    }
}

double ReflectionEngine::extractTargetMetric(
    const WorldState& state, const std::string& issue)
{
    std::string lower = issue;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower.find("cpu") != std::string::npos) return state.cpuPercent;
    if (lower.find("mem") != std::string::npos) return state.memPercent;
    if (lower.find("disk") != std::string::npos) return state.maxDiskPercent;
    if (lower.find("dns") != std::string::npos) return state.dnsWorking ? 1.0 : 0.0;
    if (lower.find("network") != std::string::npos) return state.internetReachable ? 1.0 : 0.0;
    if (lower.find("firewall") != std::string::npos) return state.firewallEnabled ? 1.0 : 0.0;
    if (lower.find("threat") != std::string::npos) return static_cast<double>(state.activeThreats.size());

    return state.healthScore;
}

} // namespace fikcer::agent

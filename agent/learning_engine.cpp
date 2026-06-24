// ============================================================================
// FikcerAgent – Learning Engine Implementation
// ============================================================================
#include "agent/learning_engine.h"
#include "utils/logger.h"

#include <algorithm>
#include <sstream>

namespace fikcer::agent {

std::vector<ActionProfile> LearningEngine::getBestActions(
    const MemoryStore& memory,
    const std::string& problemType) const
{
    // Get all incidents matching this problem type.
    auto incidents = memory.getIncidentsByProblem(problemType, 50);

    // Build profiles per action.
    std::map<std::string, ActionProfile> profiles;

    for (const auto& inc : incidents) {
        auto& prof = profiles[inc.actionTaken];
        prof.actionName = inc.actionTaken;
        prof.totalAttempts++;
        if (inc.result == "success" || inc.result == "partial") {
            prof.successRate += 1.0;
        }
        prof.avgHealthImprovement += (inc.healthAfter - inc.healthBefore);
    }

    // Normalize.
    std::vector<ActionProfile> result;
    for (auto& [_, p] : profiles) {
        if (p.totalAttempts > 0) {
            p.successRate /= p.totalAttempts;
            p.avgHealthImprovement /= p.totalAttempts;
        }
        result.push_back(p);
    }

    // Also include action_stats from memory for actions not in incidents.
    auto allStats = memory.getAllActionStats();
    for (const auto& s : allStats) {
        if (profiles.find(s.actionName) == profiles.end()) {
            ActionProfile p;
            p.actionName = s.actionName;
            p.successRate = s.successRate;
            p.totalAttempts = static_cast<int>(s.totalAttempts);
            result.push_back(p);
        }
    }

    // Sort by success rate (highest first).
    std::sort(result.begin(), result.end(),
              [](const ActionProfile& a, const ActionProfile& b) {
                  return a.successRate > b.successRate;
              });

    return result;
}

bool LearningEngine::shouldAvoidAction(
    const MemoryStore& memory,
    const std::string& actionName,
    int minSamples) const
{
    auto stats = memory.getActionStats(actionName);
    if (!stats) return false;

    // Only avoid if we have enough samples to be confident.
    if (stats->totalAttempts < minSamples) return false;

    // Avoid if success rate is below 20%.
    return stats->successRate < 0.20;
}

std::string LearningEngine::getContextForPlanner(
    const MemoryStore& memory) const
{
    std::ostringstream oss;
    oss << "LEARNING INSIGHTS:\n";

    auto allStats = memory.getAllActionStats();
    if (allStats.empty()) {
        oss << "  No historical data yet — first-time analysis.\n";
        return oss.str();
    }

    // Highlight effective actions.
    oss << "  Effective actions (>70% success):\n";
    bool hasEffective = false;
    for (const auto& s : allStats) {
        if (s.successRate >= 0.70 && s.totalAttempts >= 3) {
            oss << "    - " << s.actionName << ": "
                << static_cast<int>(s.successRate * 100) << "% success ("
                << s.totalAttempts << " uses)\n";
            hasEffective = true;
        }
    }
    if (!hasEffective) oss << "    (none yet)\n";

    // Highlight unreliable actions.
    oss << "  Unreliable actions (<30% success, 5+ attempts):\n";
    bool hasUnreliable = false;
    for (const auto& s : allStats) {
        if (s.successRate < 0.30 && s.totalAttempts >= 5) {
            oss << "    - AVOID " << s.actionName << ": only "
                << static_cast<int>(s.successRate * 100) << "% success\n";
            hasUnreliable = true;
        }
    }
    if (!hasUnreliable) oss << "    (none)\n";

    return oss.str();
}

double LearningEngine::overallSuccessRate(const MemoryStore& memory) const {
    auto allStats = memory.getAllActionStats();
    if (allStats.empty()) return 1.0;  // Assume good until proven otherwise.

    int64_t totalAttempts = 0, totalSuccesses = 0;
    for (const auto& s : allStats) {
        totalAttempts += s.totalAttempts;
        totalSuccesses += s.successes;
    }

    return (totalAttempts > 0)
        ? static_cast<double>(totalSuccesses) / static_cast<double>(totalAttempts)
        : 1.0;
}

} // namespace fikcer::agent

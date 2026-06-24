// ============================================================================
// FikcerAgent – Goal Manager Implementation
// ============================================================================
#include "agent/goal_manager.h"
#include "agent/world_state.h"
#include "utils/logger.h"

#include <algorithm>
#include <cmath>
#include <sstream>

namespace fikcer::agent {

using utils::Logger;

// ── Goal urgency ───────────────────────────────────────────────────────────

double Goal::urgency() const noexcept {
    if (satisfied) return 0.0;

    double priorityWeight = static_cast<double>(basePriority) + 1.0;

    if (isBoolean) {
        // Boolean goals: urgency is just the priority weight.
        return priorityWeight * 10.0;
    }

    // Numeric goals: urgency scales with distance from target.
    double gap = std::abs(currentValue - targetValue);
    double normalizedGap = (targetValue > 0.0)
        ? (gap / targetValue) * 100.0
        : gap;

    return priorityWeight * normalizedGap;
}

// ── GoalManager ────────────────────────────────────────────────────────────

GoalManager::GoalManager() = default;

void GoalManager::initDefaultGoals() {
    std::lock_guard lock(mutex_);
    entries_.clear();

    // 1. System Health > 90
    addGoalInternal(
        {"System Health > 90", "health", GoalPriority::CRITICAL,
         GoalPriority::CRITICAL, false, 0.0, 90.0, false,
         "Overall system health score must remain above 90%."},
        [](const WorldState& s) { return s.healthScore; }
    );

    // 2. Firewall Enabled
    addGoalInternal(
        {"Firewall Enabled", "security", GoalPriority::HIGH,
         GoalPriority::HIGH, false, 0.0, 1.0, true,
         "System firewall must be enabled at all times."},
        [](const WorldState& s) { return s.firewallEnabled ? 1.0 : 0.0; }
    );

    // 3. Antivirus Active
    addGoalInternal(
        {"Antivirus Active", "security", GoalPriority::HIGH,
         GoalPriority::HIGH, false, 0.0, 1.0, true,
         "Antivirus / system protection must be active."},
        [](const WorldState& s) { return s.defenderActive ? 1.0 : 0.0; }
    );

    // 4. No Active Threats
    addGoalInternal(
        {"No Active Threats", "security", GoalPriority::CRITICAL,
         GoalPriority::CRITICAL, false, 0.0, 0.0, false,
         "There must be zero active security threats."},
        [](const WorldState& s) {
            return static_cast<double>(s.activeThreats.size());
        }
    );

    // 5. Stable CPU Usage (< 85%)
    addGoalInternal(
        {"Stable CPU Usage", "performance", GoalPriority::MEDIUM,
         GoalPriority::MEDIUM, false, 0.0, 85.0, false,
         "CPU usage should remain below 85%."},
        [](const WorldState& s) { return s.cpuPercent; }
    );

    // 6. Stable Memory Usage (< 85%)
    addGoalInternal(
        {"Stable Memory Usage", "performance", GoalPriority::MEDIUM,
         GoalPriority::MEDIUM, false, 0.0, 85.0, false,
         "Memory usage should remain below 85%."},
        [](const WorldState& s) { return s.memPercent; }
    );

    // 7. Healthy Network Connectivity
    addGoalInternal(
        {"Healthy Network Connectivity", "stability", GoalPriority::MEDIUM,
         GoalPriority::MEDIUM, false, 0.0, 1.0, true,
         "Internet must be reachable and DNS must be working."},
        [](const WorldState& s) {
            return (s.internetReachable && s.dnsWorking) ? 1.0 : 0.0;
        }
    );

    // 8. Disk Space Available (< 90% used)
    addGoalInternal(
        {"Disk Space Available", "health", GoalPriority::MEDIUM,
         GoalPriority::MEDIUM, false, 0.0, 90.0, false,
         "No disk partition should exceed 90% usage."},
        [](const WorldState& s) { return s.maxDiskPercent; }
    );

    Logger::instance().info("GoalManager: " +
                            std::to_string(entries_.size()) +
                            " default goals registered.");
}

void GoalManager::addGoal(Goal goal, GoalEvaluator evaluator) {
    std::lock_guard lock(mutex_);
    addGoalInternal(std::move(goal), std::move(evaluator));
}

void GoalManager::addGoalInternal(Goal goal, GoalEvaluator evaluator) {
    // No lock here — called from locked methods.
    entries_.push_back({std::move(goal), std::move(evaluator)});
}

void GoalManager::evaluate(const WorldState& state) {
    std::lock_guard lock(mutex_);

    for (auto& entry : entries_) {
        auto& g = entry.goal;
        g.currentValue = entry.evaluator(state);

        if (g.isBoolean) {
            g.satisfied = (g.currentValue >= g.targetValue);
        } else if (g.name.find("No Active Threats") != std::string::npos) {
            // Special case: threat count should be 0.
            g.satisfied = (g.currentValue <= g.targetValue);
        } else if (g.name.find("Health") != std::string::npos &&
                   g.name.find(">") != std::string::npos) {
            // "Health > 90" means current must exceed target.
            g.satisfied = (g.currentValue >= g.targetValue);
        } else {
            // Usage goals: current should be below target (e.g., CPU < 85%).
            g.satisfied = (g.currentValue <= g.targetValue);
        }
    }

    reprioritize();
}

void GoalManager::reprioritize() {
    // Escalate priority for goals that are far from their target.
    for (auto& entry : entries_) {
        auto& g = entry.goal;
        g.effectivePriority = g.basePriority;

        if (!g.satisfied) {
            double u = g.urgency();
            if (u > 50.0 && g.basePriority < GoalPriority::HIGH) {
                g.effectivePriority = GoalPriority::HIGH;
            }
            if (u > 100.0) {
                g.effectivePriority = GoalPriority::CRITICAL;
            }
        }
    }

    // Sort by effective priority (highest first), then by urgency.
    std::sort(entries_.begin(), entries_.end(),
              [](const GoalEntry& a, const GoalEntry& b) {
                  if (a.goal.effectivePriority != b.goal.effectivePriority)
                      return static_cast<int>(a.goal.effectivePriority) >
                             static_cast<int>(b.goal.effectivePriority);
                  return a.goal.urgency() > b.goal.urgency();
              });
}

std::vector<Goal> GoalManager::goals() const {
    std::lock_guard lock(mutex_);
    std::vector<Goal> result;
    result.reserve(entries_.size());
    for (const auto& e : entries_) {
        result.push_back(e.goal);
    }
    return result;
}

std::vector<Goal> GoalManager::unsatisfiedGoals() const {
    std::lock_guard lock(mutex_);
    std::vector<Goal> result;
    for (const auto& e : entries_) {
        if (!e.goal.satisfied) {
            result.push_back(e.goal);
        }
    }
    return result;
}

bool GoalManager::allSatisfied() const {
    std::lock_guard lock(mutex_);
    return std::all_of(entries_.begin(), entries_.end(),
                       [](const GoalEntry& e) { return e.goal.satisfied; });
}

std::string GoalManager::summaryForPlanner() const {
    std::lock_guard lock(mutex_);

    std::ostringstream oss;
    oss << "CURRENT GOALS STATUS:\n";

    for (const auto& e : entries_) {
        const auto& g = e.goal;
        oss << "  " << (g.satisfied ? "[OK]" : "[!!]")
            << " " << g.name
            << " (current: " << g.currentValue;
        if (!g.isBoolean) {
            oss << ", target: " << g.targetValue;
        }
        oss << ", priority: " << goalPriorityTag(g.effectivePriority)
            << ")\n";
    }

    return oss.str();
}

} // namespace fikcer::agent

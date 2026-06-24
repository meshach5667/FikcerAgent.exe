// ============================================================================
// FikcerAgent – Health Score Engine Implementation
// ============================================================================
#include "agent/health_score.h"
#include "utils/logger.h"

#include <algorithm>
#include <cmath>

namespace fikcer::agent {

// ── Tier classification ────────────────────────────────────────────────────

HealthTier HealthScoreEngine::tier(double score) noexcept {
    if (score >= 90.0) return HealthTier::HEALTHY;
    if (score >= 70.0) return HealthTier::WARNING;
    return HealthTier::CRITICAL;
}

// ── Detailed component computation ─────────────────────────────────────────

HealthScoreEngine::ComponentScores HealthScoreEngine::computeDetailed(
    const WorldState& state,
    const MemoryStore& memory) const
{
    ComponentScores scores;

    // 1. CPU Stability (100 when idle, 0 when pegged at 100%).
    scores.cpuStability = std::max(0.0, 100.0 - state.cpuPercent);

    // 2. Memory Stability.
    scores.memoryStability = std::max(0.0, 100.0 - state.memPercent);

    // 3. Disk Health (based on most-used partition).
    scores.diskHealth = std::max(0.0, 100.0 - state.maxDiskPercent);

    // 4. Security Status (firewall + defender + no threats baseline).
    {
        double sec = 100.0;
        if (!state.firewallEnabled) sec -= 30.0;
        if (!state.defenderActive)  sec -= 30.0;
        // Penalize for each threat.
        sec -= static_cast<double>(state.activeThreats.size()) * 20.0;
        scores.securityStatus = std::max(0.0, sec);
    }

    // 5. Service Uptime (assume 100% if no critical services are monitored).
    {
        if (state.criticalServices.empty()) {
            // Use network as proxy for service health.
            double svc = 100.0;
            if (!state.internetReachable) svc -= 40.0;
            if (!state.dnsWorking)        svc -= 30.0;
            scores.serviceUptime = std::max(0.0, svc);
        } else {
            int running = 0;
            for (const auto& s : state.criticalServices) {
                if (s.status == "running") running++;
            }
            scores.serviceUptime = state.criticalServices.empty() ? 100.0
                : (static_cast<double>(running) /
                   static_cast<double>(state.criticalServices.size())) * 100.0;
        }
    }

    // 6. Threat Level (100 if no threats, decreases per threat).
    {
        double threat = 100.0;
        threat -= static_cast<double>(state.activeThreats.size()) * 25.0;
        threat -= static_cast<double>(state.activeAnomalies.size()) * 5.0;
        scores.threatLevel = std::max(0.0, threat);
    }

    // 7. Recovery Success Rate (from memory).
    {
        auto allStats = memory.getAllActionStats();
        if (allStats.empty()) {
            scores.recoverySuccess = 100.0;  // No data = assume good.
        } else {
            int64_t total = 0, succ = 0;
            for (const auto& s : allStats) {
                total += s.totalAttempts;
                succ  += s.successes;
            }
            scores.recoverySuccess = (total > 0)
                ? (static_cast<double>(succ) / static_cast<double>(total)) * 100.0
                : 100.0;
        }
    }

    // Composite weighted score.
    scores.composite =
        scores.cpuStability     * weightCpu +
        scores.memoryStability  * weightMemory +
        scores.diskHealth       * weightDisk +
        scores.securityStatus   * weightSecurity +
        scores.serviceUptime    * weightServices +
        scores.threatLevel      * weightThreats +
        scores.recoverySuccess  * weightRecovery;

    // Clamp to [0, 100].
    scores.composite = std::clamp(scores.composite, 0.0, 100.0);

    return scores;
}

// ── Simple composite score ─────────────────────────────────────────────────

double HealthScoreEngine::compute(const WorldState& state,
                                    const MemoryStore& memory) const
{
    return computeDetailed(state, memory).composite;
}

} // namespace fikcer::agent

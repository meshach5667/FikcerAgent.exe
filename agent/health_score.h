// ============================================================================
// FikcerAgent – Health Score Engine Interface
// ============================================================================
// Computes a composite 0-100 health score from multiple system components.
//
// Components and weights:
//   CPU Stability      15%    Memory Stability    15%
//   Disk Health        15%    Security Status     20%
//   Service Uptime     10%    Threat Level        15%
//   Recovery Success   10%
//
// Ranges:  90-100 Healthy  |  70-89 Warning  |  0-69 Critical
// ============================================================================
#pragma once

#include "agent/world_state.h"
#include "agent/memory_store.h"

#include <string>

namespace fikcer::agent {

// ── Health tier ────────────────────────────────────────────────────────────

enum class HealthTier : uint8_t {
    HEALTHY  = 0,   ///< 90-100
    WARNING  = 1,   ///< 70-89
    CRITICAL = 2,   ///< 0-69
};

[[nodiscard]] constexpr std::string_view healthTierTag(HealthTier t) noexcept {
    switch (t) {
        case HealthTier::HEALTHY:  return "HEALTHY";
        case HealthTier::WARNING:  return "WARNING";
        case HealthTier::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

// ── Health Score Engine ────────────────────────────────────────────────────

class HealthScoreEngine final {
public:
    HealthScoreEngine() = default;
    ~HealthScoreEngine() = default;

    /// Compute the composite health score.
    [[nodiscard]] double compute(const WorldState& state,
                                 const MemoryStore& memory) const;

    /// Get the health tier for a given score.
    [[nodiscard]] static HealthTier tier(double score) noexcept;

    /// Get individual component scores (for dashboard display).
    struct ComponentScores {
        double cpuStability    = 100.0;
        double memoryStability = 100.0;
        double diskHealth      = 100.0;
        double securityStatus  = 100.0;
        double serviceUptime   = 100.0;
        double threatLevel     = 100.0;
        double recoverySuccess = 100.0;
        double composite       = 100.0;
    };

    [[nodiscard]] ComponentScores computeDetailed(
        const WorldState& state,
        const MemoryStore& memory) const;

    // ── Configurable weights ───────────────────────────────────────────────
    double weightCpu      = 0.15;
    double weightMemory   = 0.15;
    double weightDisk     = 0.15;
    double weightSecurity = 0.20;
    double weightServices = 0.10;
    double weightThreats  = 0.15;
    double weightRecovery = 0.10;
};

} // namespace fikcer::agent

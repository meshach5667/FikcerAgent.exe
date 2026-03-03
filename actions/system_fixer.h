// ============================================================================
// FikcerAgent – System Fixer Interface
// ============================================================================
// Executes real system-level fixes based on Gemini AI recommendations:
//
//   • Clear caches & temp files (reclaim disk space)
//   • Flush DNS cache (fix DNS issues)
//   • Kill malicious / suspicious processes
//   • Reset network stack (fix connectivity)
//   • Purge memory (relieve memory pressure)
//   • Run system maintenance tasks
//   • Windows: sfc, DISM, Defender scans, driver refresh
//
// All fixes are logged with audit trail.  DRY_RUN mode logs but doesn't act.
// ============================================================================
#pragma once

#include "ai/gemini_client.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace fikcer::actions {

// ── Fix result record ──────────────────────────────────────────────────────

struct FixRecord {
    std::string problemType;    ///< DISK_SPACE, MALWARE, NETWORK, etc.
    std::string severity;       ///< LOW, MEDIUM, HIGH, CRITICAL
    std::string description;    ///< What was wrong.
    std::string fixApplied;     ///< What fix was executed.
    std::string fixOutput;      ///< Output from the fix command.
    bool        success = false;
    bool        dryRun  = false;
    std::chrono::steady_clock::time_point timestamp;
};

/// Callback fired after each fix attempt.
using FixCallback = std::function<void(const FixRecord&)>;

// ── System Fixer ───────────────────────────────────────────────────────────

class SystemFixer final {
public:
    SystemFixer() = default;
    ~SystemFixer() = default;

    SystemFixer(const SystemFixer&) = delete;
    SystemFixer& operator=(const SystemFixer&) = delete;

    /// Register a callback for fix events.
    void setCallback(FixCallback cb);

    /// Process a batch of Gemini-identified problems and fix them.
    /// Returns all fix records.
    std::vector<FixRecord> fixProblems(
        const std::vector<ai::GeminiProblem>& problems);

    /// Get statistics.
    [[nodiscard]] uint64_t totalFixesApplied() const noexcept;
    [[nodiscard]] uint64_t totalFixesFailed()  const noexcept;
    [[nodiscard]] uint64_t totalKills()        const noexcept;

private:
    // ── Per-type handlers ──────────────────────────────────────────────────
    FixRecord executeCommand(const ai::GeminiProblem& p);
    FixRecord killProcess(const ai::GeminiProblem& p);
    FixRecord purgeMemory(const ai::GeminiProblem& p);
    FixRecord logOnly(const ai::GeminiProblem& p);

    /// Validate a command before execution (safety check).
    [[nodiscard]] bool isCommandSafe(const std::string& cmd) const;

    // ── State ──────────────────────────────────────────────────────────────
    FixCallback callback_;
    mutable std::mutex mutex_;

    std::atomic<uint64_t> totalFixesApplied_{0};
    std::atomic<uint64_t> totalFixesFailed_{0};
    std::atomic<uint64_t> totalKills_{0};
};

} // namespace fikcer::actions

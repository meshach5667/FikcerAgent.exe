// ============================================================================
// FikcerAgent – Auto-Healer Implementation
// ============================================================================
#include "actions/auto_healer.h"
#include "config.h"
#include "utils/logger.h"

#include <cstdlib>
#include <sstream>

#ifdef __APPLE__
#   include <unistd.h>
#   include <spawn.h>
    extern char** environ;
#endif

namespace fikcer::actions {

using utils::Logger;

// ── Construction ───────────────────────────────────────────────────────────

AutoHealer::AutoHealer(ProcessManager& procMgr)
    : procMgr_(procMgr)
{}

void AutoHealer::setCallback(HealCallback cb) {
    callback_ = std::move(cb);
}

// ── Statistics ─────────────────────────────────────────────────────────────

uint64_t AutoHealer::totalTerminations() const noexcept {
    return totalTerminations_.load(std::memory_order_relaxed);
}
uint64_t AutoHealer::totalRestarts() const noexcept {
    return totalRestarts_.load(std::memory_order_relaxed);
}
uint64_t AutoHealer::totalPurgeCaches() const noexcept {
    return totalPurgeCaches_.load(std::memory_order_relaxed);
}

// ── Main handler ───────────────────────────────────────────────────────────

std::vector<HealRecord> AutoHealer::handleAnomalies(
    const std::vector<ai::Anomaly>& anomalies)
{
    std::vector<HealRecord> records;
    records.reserve(anomalies.size());

    for (const auto& a : anomalies) {
        HealRecord rec;

        switch (a.type) {
            case ai::AnomalyType::PROCESS_CPU_HOG:
                rec = handleProcessCpuHog(a);
                break;
            case ai::AnomalyType::PROCESS_MEM_HOG:
                rec = handleProcessMemHog(a);
                break;
            case ai::AnomalyType::MEMORY_SPIKE:
            case ai::AnomalyType::MEMORY_LEAK:
                rec = handleMemorySpike(a);
                break;
            case ai::AnomalyType::SYSTEM_OVERLOAD:
                rec = handleSystemOverload(a);
                break;
            default:
                rec = logOnly(a);
                break;
        }

        // Fire callback.
        if (callback_) {
            try { callback_(rec); }
            catch (...) {
                Logger::instance().error("Exception in heal callback.");
            }
        }

        records.push_back(std::move(rec));
    }

    return records;
}

// ── Process CPU hog ────────────────────────────────────────────────────────

HealRecord AutoHealer::handleProcessCpuHog(const ai::Anomaly& a) {
    HealRecord rec;
    rec.cause       = a.type;
    rec.severity    = a.severity;
    rec.pid         = a.relatedPid;
    rec.processName = a.relatedProcess;
    rec.timestamp   = std::chrono::steady_clock::now();

    // Check whitelist — only touch whitelisted processes.
    if (!procMgr_.isWhitelisted(a.relatedProcess)) {
        rec.action      = HealAction::LOG_ONLY;
        rec.description = "CPU hog '" + a.relatedProcess + "' (PID " +
                          std::to_string(a.relatedPid) +
                          ") not whitelisted — logging only.";
        rec.success     = true;
        Logger::instance().warn(rec.description);
        return rec;
    }

    // Check per-PID heal budget.
    {
        std::lock_guard lock(mutex_);
        auto& hist = pidHistory_[a.relatedPid];
        if (hist.healAttempts >= config::MAX_RESTART_ATTEMPTS) {
            rec.action      = HealAction::LOG_ONLY;
            rec.description = "Max heal attempts reached for PID " +
                              std::to_string(a.relatedPid) + " — skipping.";
            rec.success     = false;
            Logger::instance().error(rec.description);
            return rec;
        }
    }

    // Dry-run guard.
    if constexpr (config::DRY_RUN) {
        rec.action      = HealAction::LOG_ONLY;
        rec.description = "[DRY-RUN] Would terminate CPU hog: " +
                          a.relatedProcess;
        rec.success     = true;
        Logger::instance().info(rec.description);
        return rec;
    }

    // Only terminate (don't restart) for CPU hogs with MEDIUM severity.
    // For HIGH+ severity, terminate and restart.
    if (a.severity >= ai::Severity::HIGH) {
        // Get the full path before killing.
        auto procs = procMgr_.enumerateProcesses();
        std::string fullPath;
        for (const auto& p : procs) {
            if (p.pid == a.relatedPid) {
                fullPath = p.fullPath;
                break;
            }
        }

        Logger::instance().warn("AUTO-HEAL: Terminating CPU hog '" +
                                a.relatedProcess + "' (PID " +
                                std::to_string(a.relatedPid) + ")");

        bool killed = ProcessManager::terminateProcess(a.relatedPid);
        if (killed) {
            totalTerminations_.fetch_add(1, std::memory_order_relaxed);

            if (!fullPath.empty()) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(config::RESTART_DELAY_MS));

                uint32_t newPid = ProcessManager::restartProcess(fullPath);
                if (newPid > 0) {
                    totalRestarts_.fetch_add(1, std::memory_order_relaxed);
                    rec.action      = HealAction::TERMINATE_RESTART;
                    rec.description = "Terminated and restarted '" +
                                     a.relatedProcess + "' as PID " +
                                     std::to_string(newPid);
                    rec.success     = true;
                    Logger::instance().info(rec.description);
                } else {
                    rec.action      = HealAction::TERMINATE;
                    rec.description = "Terminated '" + a.relatedProcess +
                                     "' but restart failed.";
                    rec.success     = false;
                    Logger::instance().error(rec.description);
                }
            } else {
                rec.action      = HealAction::TERMINATE;
                rec.description = "Terminated '" + a.relatedProcess +
                                  "' (path unknown, cannot restart).";
                rec.success     = true;
                Logger::instance().warn(rec.description);
            }
        } else {
            rec.action      = HealAction::LOG_ONLY;
            rec.description = "Failed to terminate PID " +
                              std::to_string(a.relatedPid);
            rec.success     = false;
            Logger::instance().error(rec.description);
        }
    } else {
        // Medium/low severity — just log.
        rec.action      = HealAction::LOG_ONLY;
        rec.description = "CPU hog detected (medium severity) — monitoring: " +
                          a.relatedProcess;
        rec.success     = true;
        Logger::instance().info(rec.description);
    }

    // Update heal history.
    {
        std::lock_guard lock(mutex_);
        auto& hist = pidHistory_[a.relatedPid];
        hist.healAttempts++;
        hist.lastAttempt = std::chrono::steady_clock::now();
    }

    return rec;
}

// ── Process memory hog ─────────────────────────────────────────────────────

HealRecord AutoHealer::handleProcessMemHog(const ai::Anomaly& a) {
    // Same logic as CPU hog — reuse with different messaging.
    HealRecord rec = handleProcessCpuHog(a);
    // Override description for clarity.
    if (rec.action == HealAction::LOG_ONLY && rec.success) {
        rec.description = "Memory hog '" + a.relatedProcess +
                          "' — " + rec.description;
    }
    return rec;
}

// ── Memory spike / leak ────────────────────────────────────────────────────

HealRecord AutoHealer::handleMemorySpike(const ai::Anomaly& a) {
    HealRecord rec;
    rec.cause       = a.type;
    rec.severity    = a.severity;
    rec.timestamp   = std::chrono::steady_clock::now();

    // Try to purge system caches to free memory.
    if constexpr (config::DRY_RUN) {
        rec.action      = HealAction::LOG_ONLY;
        rec.description = "[DRY-RUN] Would purge system caches.";
        rec.success     = true;
        Logger::instance().info(rec.description);
        return rec;
    }

    if (a.severity >= ai::Severity::MEDIUM) {
        Logger::instance().warn("AUTO-HEAL: Attempting memory cache purge...");

        if (purgeSystemCaches()) {
            totalPurgeCaches_.fetch_add(1, std::memory_order_relaxed);
            rec.action      = HealAction::PURGE_CACHE;
            rec.description = "System cache purge triggered to reclaim memory.";
            rec.success     = true;
            Logger::instance().info(rec.description);
        } else {
            rec.action      = HealAction::LOG_ONLY;
            rec.description = "Cache purge not available or failed.";
            rec.success     = false;
            Logger::instance().warn(rec.description);
        }
    } else {
        rec.action      = HealAction::LOG_ONLY;
        rec.description = "Memory issue detected (low severity) — monitoring.";
        rec.success     = true;
        Logger::instance().info(rec.description);
    }

    return rec;
}

// ── System overload ────────────────────────────────────────────────────────

HealRecord AutoHealer::handleSystemOverload(const ai::Anomaly& a) {
    HealRecord rec;
    rec.cause       = a.type;
    rec.severity    = ai::Severity::CRITICAL;
    rec.timestamp   = std::chrono::steady_clock::now();

    Logger::instance().fatal(
        "SYSTEM OVERLOAD DETECTED — initiating emergency response.");

    if constexpr (config::DRY_RUN) {
        rec.action      = HealAction::LOG_ONLY;
        rec.description = "[DRY-RUN] Would initiate emergency resource reclamation.";
        rec.success     = true;
        Logger::instance().info(rec.description);
        return rec;
    }

    // Step 1: Purge caches.
    purgeSystemCaches();
    totalPurgeCaches_.fetch_add(1, std::memory_order_relaxed);

    // Step 2: Find the top CPU-hogging whitelisted processes and terminate.
    auto allProcs = procMgr_.enumerateProcesses();
    auto resources = ai::AnomalyDetector::sampleProcessResources();

    // Sort by CPU usage descending.
    std::sort(resources.begin(), resources.end(),
              [](const auto& a, const auto& b) {
                  return a.cpuPercent > b.cpuPercent;
              });

    unsigned int terminated = 0;
    for (const auto& res : resources) {
        if (terminated >= 2) break;   // Don't go overboard.

        if (procMgr_.isWhitelisted(res.name) && res.cpuPercent > 50.0) {
            Logger::instance().warn(
                "Emergency: Terminating '" + res.name + "' (PID " +
                std::to_string(res.pid) + ", CPU " +
                std::to_string(static_cast<int>(res.cpuPercent)) + "%)");

            if (ProcessManager::terminateProcess(res.pid)) {
                totalTerminations_.fetch_add(1, std::memory_order_relaxed);
                terminated++;
            }
        }
    }

    rec.action      = HealAction::TERMINATE;
    rec.description = "Emergency response: purged caches, terminated " +
                      std::to_string(terminated) + " processes.";
    rec.success     = (terminated > 0);
    Logger::instance().info(rec.description);

    return rec;
}

// ── Log-only fallback ──────────────────────────────────────────────────────

HealRecord AutoHealer::logOnly(const ai::Anomaly& a) {
    HealRecord rec;
    rec.action      = HealAction::LOG_ONLY;
    rec.cause       = a.type;
    rec.severity    = a.severity;
    rec.pid         = a.relatedPid;
    rec.processName = a.relatedProcess;
    rec.description = "Anomaly logged: " + a.description;
    rec.success     = true;
    rec.timestamp   = std::chrono::steady_clock::now();

    Logger::instance().info(rec.description);
    return rec;
}

// ── Cache purge ────────────────────────────────────────────────────────────

bool AutoHealer::purgeSystemCaches() {
#ifdef __APPLE__
    // macOS: `purge` command clears disk caches (needs root).
    // Instead, we use a safer approach: advise the kernel to reclaim.
    // sync() flushes filesystem buffers, which triggers cache reclamation.
    sync();
    Logger::instance().info("Triggered filesystem sync for cache pressure.");
    return true;

#elif defined(_WIN32)
    // Windows: EmptyWorkingSet for the current process at minimum.
    // System-wide cache purge requires elevated privileges.
    // For now, we log the recommendation.
    Logger::instance().info("Memory cache purge requested (Windows). "
                            "Consider running RamMap or restarting services.");
    return false;

#else
    return false;
#endif
}

} // namespace fikcer::actions

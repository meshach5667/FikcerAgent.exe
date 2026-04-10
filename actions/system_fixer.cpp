// ============================================================================
// FikcerAgent – System Fixer Implementation
// ============================================================================
#include "actions/system_fixer.h"
#include "actions/process_manager.h"
#include "config.h"
#include "utils/exec.h"
#include "utils/logger.h"

#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <sstream>

#ifdef __APPLE__
#   include <unistd.h>
#   include <signal.h>
#endif

namespace fikcer::actions {

using utils::Logger;
using utils::exec;

// ── Callback ───────────────────────────────────────────────────────────────

void SystemFixer::setCallback(FixCallback cb) {
    callback_ = std::move(cb);
}

// ── Statistics ─────────────────────────────────────────────────────────────

uint64_t SystemFixer::totalFixesApplied() const noexcept {
    return totalFixesApplied_.load(std::memory_order_relaxed);
}
uint64_t SystemFixer::totalFixesFailed() const noexcept {
    return totalFixesFailed_.load(std::memory_order_relaxed);
}
uint64_t SystemFixer::totalKills() const noexcept {
    return totalKills_.load(std::memory_order_relaxed);
}

// ── Command Safety Check ───────────────────────────────────────────────────

bool SystemFixer::isCommandSafe(const std::string& cmd) const {
    std::string lower = cmd;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Block dangerous commands that could destroy the system.
    static const std::vector<std::string> BLOCKED_PATTERNS = {
        "rm -rf /",          // Nuke everything
        "rm -rf /*",         // Same
        "mkfs",              // Format disk
        "dd if=",            // Raw disk write
        "format c:",         // Windows format
        ":(){",              // Fork bomb
        "chmod -r 000 /",    // Remove all permissions
        "chown -r",          // Recursive ownership change on /
        "> /dev/sda",        // Overwrite disk
        "curl | sh",         // Pipe untrusted code
        "curl | bash",       // Same
        "wget | sh",         // Same
        "shutdown",          // Don't let AI shut down the machine
        "reboot",            // Don't let AI reboot
        "halt",              // Don't let AI halt
        "init 0",            // Shutdown
        "init 6",            // Reboot
        "passwd",            // Don't change passwords
        "useradd",           // Don't create users
        "userdel",           // Don't delete users
        "visudo",            // Don't modify sudoers
        "launchctl unload",  // Don't unload critical services
    };

    for (const auto& blocked : BLOCKED_PATTERNS) {
        if (lower.find(blocked) != std::string::npos) {
            Logger::instance().error(
                "BLOCKED unsafe command from AI: " + cmd);
            return false;
        }
    }

    // Allow known safe command prefixes.
    static const std::vector<std::string> SAFE_PREFIXES = {
        "rm -rf ~/library/caches",
        "rm -rf /tmp/",
        "rm -rf ~/library/logs",
        "rm -f /tmp/",
        "dscacheutil",
        "killall -hup mdnsresponder",
        "purge",
        "periodic",
        "sync",
        "kill ",
        "kill -9 ",
        "kill -15 ",
        "dns",
        "flush",
        "ipconfig",
        "netsh",
        "sfc ",
        "dism ",
        "mpcmdrun",
        "networksetup",
        "ifconfig",
        "route",
        "arp",
        "open ",
        "xattr",
        "mdutil",
        "tmutil",
        "softwareupdate",
        "brew ",
        "diskutil repairpermissions",
        "diskutil verifyvolume",
    };

    for (const auto& safe : SAFE_PREFIXES) {
        if (lower.find(safe) != std::string::npos) {
            return true;
        }
    }

    // If we don't recognise the command, log warning but still allow
    // non-destructive looking commands.
    Logger::instance().warn(
        "Unrecognised fix command from AI (allowing cautiously): " + cmd);
    return true;
}

// ── Fix Problems ───────────────────────────────────────────────────────────

std::vector<FixRecord> SystemFixer::fixProblems(
    const std::vector<ai::GeminiProblem>& problems)
{
    std::vector<FixRecord> records;
    records.reserve(problems.size());

    for (const auto& p : problems) {
        FixRecord rec;

        if (p.fixType == "COMMAND") {
            rec = executeCommand(p);
        } else if (p.fixType == "KILL") {
            rec = killProcess(p);
        } else if (p.fixType == "PURGE") {
            rec = purgeMemory(p);
        } else {
            rec = logOnly(p);
        }

        // Fire callback.
        if (callback_) {
            try { callback_(rec); }
            catch (...) {
                Logger::instance().error("Exception in fix callback.");
            }
        }

        records.push_back(std::move(rec));
    }

    return records;
}

// ── Execute Shell Command Fix ──────────────────────────────────────────────

FixRecord SystemFixer::executeCommand(const ai::GeminiProblem& p) {
    FixRecord rec;
    rec.problemType  = p.type;
    rec.severity     = p.severity;
    rec.description  = p.description;
    rec.timestamp    = std::chrono::steady_clock::now();

    if constexpr (config::DRY_RUN) {
        rec.fixApplied = "[DRY-RUN] Would run: " + p.fixTarget;
        rec.success    = true;
        rec.dryRun     = true;
        Logger::instance().info(rec.fixApplied);
        return rec;
    }

    // Safety check.
    if (!isCommandSafe(p.fixTarget)) {
        rec.fixApplied = "BLOCKED (unsafe): " + p.fixTarget;
        rec.success    = false;
        totalFixesFailed_.fetch_add(1, std::memory_order_relaxed);
        Logger::instance().error(rec.fixApplied);
        return rec;
    }

    Logger::instance().info("Executing fix: " + p.fixTarget +
                            " (" + p.fixDescription + ")");

    // Execute the command and capture output.
    rec.fixApplied = p.fixTarget;
    rec.fixOutput  = exec(p.fixTarget + " 2>&1");

    // Check exit code by running again with just status.
    int status = utils::execStatus(p.fixTarget);
    rec.success = (status == 0);

    if (rec.success) {
        totalFixesApplied_.fetch_add(1, std::memory_order_relaxed);
        Logger::instance().info("Fix succeeded: " + p.fixDescription);
    } else {
        totalFixesFailed_.fetch_add(1, std::memory_order_relaxed);
        Logger::instance().warn("Fix may have failed (exit " +
                                std::to_string(status) + "): " +
                                p.fixDescription);
    }

    return rec;
}

// ── Kill Process Fix ───────────────────────────────────────────────────────

FixRecord SystemFixer::killProcess(const ai::GeminiProblem& p) {
    FixRecord rec;
    rec.problemType  = p.type;
    rec.severity     = p.severity;
    rec.description  = p.description;
    rec.timestamp    = std::chrono::steady_clock::now();

    uint32_t pid = 0;
    try {
        pid = static_cast<uint32_t>(std::stoul(p.fixTarget));
    } catch (...) {
        rec.fixApplied = "Invalid PID: " + p.fixTarget;
        rec.success    = false;
        totalFixesFailed_.fetch_add(1, std::memory_order_relaxed);
        Logger::instance().error(rec.fixApplied);
        return rec;
    }

    // Never kill PID 0, 1, or our own process.
    if (pid <= 1 || pid == static_cast<uint32_t>(getpid())) {
        rec.fixApplied = "Refusing to kill protected PID: " +
                         std::to_string(pid);
        rec.success    = false;
        Logger::instance().error(rec.fixApplied);
        return rec;
    }

    if constexpr (config::DRY_RUN) {
        rec.fixApplied = "[DRY-RUN] Would kill PID " + std::to_string(pid);
        rec.success    = true;
        rec.dryRun     = true;
        Logger::instance().info(rec.fixApplied);
        return rec;
    }

    Logger::instance().warn("KILLING suspicious process PID " +
                            std::to_string(pid) + ": " + p.fixDescription);

    // Use ProcessManager's robust and secure termination logic.
    rec.success = ProcessManager::terminateProcess(pid);

    rec.fixApplied = "Killed PID " + std::to_string(pid);

    if (rec.success) {
        totalKills_.fetch_add(1, std::memory_order_relaxed);
        totalFixesApplied_.fetch_add(1, std::memory_order_relaxed);
        Logger::instance().info("Successfully killed PID " +
                                std::to_string(pid));
    } else {
        totalFixesFailed_.fetch_add(1, std::memory_order_relaxed);
        Logger::instance().error("Failed to kill PID " +
                                 std::to_string(pid));
    }

    return rec;
}

// ── Memory Purge Fix ───────────────────────────────────────────────────────

FixRecord SystemFixer::purgeMemory(const ai::GeminiProblem& p) {
    FixRecord rec;
    rec.problemType  = p.type;
    rec.severity     = p.severity;
    rec.description  = p.description;
    rec.timestamp    = std::chrono::steady_clock::now();

    if constexpr (config::DRY_RUN) {
        rec.fixApplied = "[DRY-RUN] Would purge memory.";
        rec.success    = true;
        rec.dryRun     = true;
        Logger::instance().info(rec.fixApplied);
        return rec;
    }

    Logger::instance().info("Purging memory to relieve pressure...");

#ifdef __APPLE__
    sync();  // Flush filesystem buffers.
    rec.fixApplied = "Triggered filesystem sync for memory reclamation.";
    rec.success    = true;
#elif defined(_WIN32)
    rec.fixApplied = "Memory purge requested (Windows).";
    rec.success    = false;
#else
    rec.fixApplied = "Memory purge not available on this platform.";
    rec.success    = false;
#endif

    if (rec.success) {
        totalFixesApplied_.fetch_add(1, std::memory_order_relaxed);
    }

    Logger::instance().info(rec.fixApplied);
    return rec;
}

// ── Log-Only (no auto-fix available) ───────────────────────────────────────

FixRecord SystemFixer::logOnly(const ai::GeminiProblem& p) {
    FixRecord rec;
    rec.problemType  = p.type;
    rec.severity     = p.severity;
    rec.description  = p.description;
    rec.fixApplied   = "No auto-fix available: " + p.fixDescription;
    rec.success      = true;
    rec.timestamp    = std::chrono::steady_clock::now();

    Logger::instance().info("[INFO-ONLY] " + p.type + ": " + p.description +
                            " — " + p.fixDescription);
    return rec;
}

} // namespace fikcer::actions

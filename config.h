// ============================================================================
// FikcerAgent – Global Configuration
// ============================================================================
// Central place for all tuneable constants. Change values here instead of
// scattering magic numbers throughout the codebase.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace fikcer::config {

// ── Monitoring ─────────────────────────────────────────────────────────────
/// Interval (ms) between system-stats snapshots printed to the console.
inline constexpr unsigned int MONITOR_INTERVAL_MS = 5000;

/// CPU usage threshold (%) that triggers a warning log entry.
inline constexpr double CPU_WARNING_THRESHOLD = 90.0;

/// Memory usage threshold (%) that triggers a warning log entry.
inline constexpr double MEMORY_WARNING_THRESHOLD = 90.0;

// ── Process Manager ────────────────────────────────────────────────────────
/// Interval (ms) between hung-process scans.
inline constexpr unsigned int PROCESS_SCAN_INTERVAL_MS = 10000;

/// Timeout (ms) for SendMessageTimeout when probing a window.
inline constexpr unsigned int HANG_DETECT_TIMEOUT_MS = 5000;

/// Maximum number of process IDs we enumerate in one call.
inline constexpr std::size_t MAX_PROCESS_IDS = 4096;

/// Grace period (ms) after terminating a process before restarting it.
inline constexpr unsigned int RESTART_DELAY_MS = 2000;

/// Maximum consecutive restart attempts per process before giving up.
inline constexpr unsigned int MAX_RESTART_ATTEMPTS = 3;

// ── Logger ─────────────────────────────────────────────────────────────────
/// Default log directory (relative to the executable).
inline constexpr std::string_view LOG_DIRECTORY = "logs";

/// Maximum log file size in bytes before rotation (5 MB).
inline constexpr std::size_t MAX_LOG_FILE_SIZE = 5ULL * 1024 * 1024;

/// Maximum number of rotated log files to keep.
inline constexpr std::size_t MAX_LOG_FILES = 10;

/// Log file base name.
inline constexpr std::string_view LOG_FILE_PREFIX = "fikcerAgent";

// ── Safety ─────────────────────────────────────────────────────────────────
/// If true, the agent will only monitor and log — never kill/restart.
inline constexpr bool DRY_RUN = false;

} // namespace fikcer::config

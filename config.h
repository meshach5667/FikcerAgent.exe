//
// FikcerAgent – Global Configuration
// 
// Central place for all tuneable constants. Change values here instead of
// scattering magic numbers throughout the codebase.
// 
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace fikcer::config {

// ── Monitorin
/// Interval (ms) between system-stats snapshots printed to the console.
inline constexpr unsigned int MONITOR_INTERVAL_MS = 5000;

/// CPU usage threshold (%) that triggers a warning log entry.
inline constexpr double CPU_WARNING_THRESHOLD = 90.0;

/// Memory usage threshold (%) that triggers a warning log entry.
inline constexpr double MEMORY_WARNING_THRESHOLD = 90.0;

// ── Process Manager 
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

// ── Logger 
/// Default log directory (relative to the executable).
inline constexpr std::string_view LOG_DIRECTORY = "logs";

/// Maximum log file size in bytes before rotation (5 MB).
inline constexpr std::size_t MAX_LOG_FILE_SIZE = 5ULL * 1024 * 1024;

/// Maximum number of rotated log files to keep.
inline constexpr std::size_t MAX_LOG_FILES = 10;

/// Log file base name.
inline constexpr std::string_view LOG_FILE_PREFIX = "fikcerAgent";

// ── AI / Anomaly Detection ─────────────────────────────────────────────────
/// Interval (ms) between heuristic AI analysis passes.
inline constexpr unsigned int AI_SCAN_INTERVAL_MS = 5000;

/// Interval (ms) between deep system scans + Gemini analysis.
/// Longer interval because it involves network calls and shell commands.
inline constexpr unsigned int DEEP_SCAN_INTERVAL_MS = 60000;  // 60 seconds

/// Gemini model to use (gemini-2.0-flash is fast and cheap).
inline constexpr std::string_view GEMINI_MODEL = "gemini-2.0-flash";

/// Maximum Gemini API calls per hour (rate limiting).
inline constexpr unsigned int GEMINI_MAX_CALLS_PER_HOUR = 30;

/// A single process using more than this % CPU is flagged as a hog.
inline constexpr double PROCESS_CPU_HOG_THRESHOLD = 80.0;

/// A single process using more than this amount of RAM is flagged.
inline constexpr uint64_t PROCESS_MEM_HOG_BYTES = 2ULL * 1024 * 1024 * 1024; // 2 GB

/// Number of consecutive samples for memory-leak detection window.
inline constexpr unsigned int MEMORY_LEAK_WINDOW_SAMPLES = 12;

/// CPU ramp threshold – % increase per sample that triggers a ramp alert.
inline constexpr double CPU_RAMP_DELTA = 15.0;

/// Minimum cooldown (ms) between heal actions on the same PID.
inline constexpr unsigned int HEAL_COOLDOWN_MS = 30000;

/// Maximum heal attempts per PID before the healer gives up.
inline constexpr unsigned int MAX_HEAL_ATTEMPTS_PER_PID = 3;

// ── Safety ─────────────────────────────────────────────────────────────────
/// If true, the agent will only monitor and log — never kill/restart.
inline constexpr bool DRY_RUN = false;

} // namespace fikcer::config

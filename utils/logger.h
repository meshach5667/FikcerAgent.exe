/**
 * @file logger.h
 * @brief Thread-safe logging utility with timestamped output and log rotation.
 *
 * FikcerAgent – Autonomous Self-Healing System Agent
 * Module: Utils / Logger
 *
 * Responsibilities:
 *   - Write log entries to a timestamped file and optionally to stderr.
 *   - Rotate log files when they exceed a configurable size threshold.
 *   - Guarantee thread safety so any module can log from any thread.
 *
 * Security notes:
 *   - File paths are validated before opening.
 *   - No user-supplied strings are interpreted as format specifiers.
 */

#ifndef FIKCERAGENT_UTILS_LOGGER_H
#define FIKCERAGENT_UTILS_LOGGER_H

#include <cstddef>     // size_t
#include <filesystem>  // std::filesystem::path
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>

namespace fikcer::utils {

/// Severity levels – ordered by increasing severity.
enum class LogLevel : int {
    kDebug = 0,
    kInfo  = 1,
    kWarn  = 2,
    kError = 3,
    kFatal = 4,
};

/**
 * @brief Converts a LogLevel to its human-readable tag.
 */
[[nodiscard]] constexpr std::string_view LogLevelToString(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::kDebug: return "DEBUG";
        case LogLevel::kInfo:  return "INFO ";
        case LogLevel::kWarn:  return "WARN ";
        case LogLevel::kError: return "ERROR";
        case LogLevel::kFatal: return "FATAL";
        default:               return "?????";
    }
}

/**
 * @class Logger
 * @brief Singleton, thread-safe file logger with automatic rotation.
 *
 * Usage:
 *   Logger::Instance().Init("logs", 5 * 1024 * 1024);  // 5 MiB max
 *   Logger::Instance().Log(LogLevel::kInfo, "System started");
 */
class Logger final {
public:
    // ---- Singleton access ------------------------------------------------
    [[nodiscard]] static Logger& Instance() noexcept;

    // Non-copyable, non-movable (singleton).
    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&)                 = delete;
    Logger& operator=(Logger&&)      = delete;

    // ---- Configuration ---------------------------------------------------

    /**
     * @brief Initialise the logger.  Must be called once before any Log().
     * @param log_directory  Folder where log files are stored (created if absent).
     * @param max_file_bytes Maximum size of a single log file before rotation.
     * @param min_level      Minimum severity that will be written.
     * @param echo_stderr    Also print to stderr when true.
     * @return true on success, false if the directory could not be created.
     */
    bool Init(const std::filesystem::path& log_directory,
              std::size_t max_file_bytes = 5 * 1024 * 1024,
              LogLevel min_level         = LogLevel::kInfo,
              bool echo_stderr           = true);

    /**
     * @brief Flush and close the current log file.  Safe to call multiple times.
     */
    void Shutdown() noexcept;

    // ---- Logging ---------------------------------------------------------

    /**
     * @brief Write a single log entry.
     * @param level    Severity.
     * @param message  The text to log (no trailing newline needed).
     */
    void Log(LogLevel level, std::string_view message);

    // Convenience wrappers.
    void Debug(std::string_view msg) { Log(LogLevel::kDebug, msg); }
    void Info(std::string_view msg)  { Log(LogLevel::kInfo,  msg); }
    void Warn(std::string_view msg)  { Log(LogLevel::kWarn,  msg); }
    void Error(std::string_view msg) { Log(LogLevel::kError, msg); }
    void Fatal(std::string_view msg) { Log(LogLevel::kFatal, msg); }

private:
    Logger() = default;
    ~Logger();

    // ---- Internal helpers ------------------------------------------------

    /**
     * @brief Generate a new log filename based on the current timestamp.
     */
    [[nodiscard]] std::filesystem::path MakeLogFilePath() const;

    /**
     * @brief Open (or rotate to) a fresh log file.  Caller must hold mutex_.
     */
    bool OpenNewFile();

    /**
     * @brief Rotate the log if the current file exceeds max_file_bytes_.
     *        Caller must hold mutex_.
     */
    void RotateIfNeeded();

    /**
     * @brief Build a "[YYYY-MM-DD HH:MM:SS.mmm]" timestamp string.
     */
    [[nodiscard]] static std::string Timestamp();

    // ---- Data members (all guarded by mutex_) ----------------------------
    std::mutex               mutex_;
    std::ofstream            file_;
    std::filesystem::path    log_dir_;
    std::size_t              max_file_bytes_ = 5 * 1024 * 1024;
    std::size_t              current_bytes_  = 0;
    LogLevel                 min_level_      = LogLevel::kInfo;
    bool                     echo_stderr_    = true;
    bool                     initialised_    = false;
};

}  // namespace fikcer::utils

// ---- Macros for convenience (optional) ------------------------------------
// These are short-hands that automatically use the singleton instance.
#define FIKCER_LOG_DEBUG(msg) ::fikcer::utils::Logger::Instance().Debug(msg)
#define FIKCER_LOG_INFO(msg)  ::fikcer::utils::Logger::Instance().Info(msg)
#define FIKCER_LOG_WARN(msg)  ::fikcer::utils::Logger::Instance().Warn(msg)
#define FIKCER_LOG_ERROR(msg) ::fikcer::utils::Logger::Instance().Error(msg)
#define FIKCER_LOG_FATAL(msg) ::fikcer::utils::Logger::Instance().Fatal(msg)

#endif  // FIKCERAGENT_UTILS_LOGGER_H

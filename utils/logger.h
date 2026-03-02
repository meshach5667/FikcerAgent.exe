
// FikcerAgent – Logger Interface

// Thread-safe, rotating file logger.  All public methods are safe to call
// from any thread without external synchronization.

#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>

namespace fikcer::utils {

/// Severity levels – stored as `uint8_t` under the hood for speed.
enum class LogLevel : std::uint8_t {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERR   = 4,   // "ERROR" clashes with Windows macros
    FATAL = 5,
};

/// Convert a LogLevel to its short tag (e.g. "INFO", "WARN").
[[nodiscard]] constexpr std::string_view logLevelTag(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERR:   return "ERROR";
        case LogLevel::FATAL: return "FATAL";
    }
    return "?????";
}

// ────────────────────────────────────────────────────────────────────────────
/// Thread-safe rotating file logger (singleton).
///
/// Usage:
///   auto& log = Logger::instance();
///   log.init("logs", "fikcerAgent", 5*1024*1024, 10);
///   log.info("System started");
///   log.error("Failed to open handle: {}", GetLastError());
// ────────────────────────────────────────────────────────────────────────────
class Logger final {
public:
    // ── Singleton access ───────────────────────────────────────────────────
    [[nodiscard]] static Logger& instance() noexcept;

    // Non-copyable, non-movable
    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&)                 = delete;
    Logger& operator=(Logger&&)      = delete;

    // ── Initialization ─────────────────────────────────────────────────────
    /// @param logDir       Directory for log files (created if absent).
    /// @param filePrefix   Base name for log files.
    /// @param maxFileSize  Max bytes per file before rotation.
    /// @param maxFiles     Max rotated files to keep.
    /// @param minLevel     Minimum severity to record.
    /// @return true on success.
    bool init(const std::filesystem::path& logDir,
              std::string_view             filePrefix,
              std::size_t                  maxFileSize,
              std::size_t                  maxFiles,
              LogLevel                     minLevel = LogLevel::INFO);

    /// Flush and close the log file.
    void shutdown();

    // ── Logging shortcuts ──────────────────────────────────────────────────
    void trace(std::string_view msg);
    void debug(std::string_view msg);
    void info (std::string_view msg);
    void warn (std::string_view msg);
    void error(std::string_view msg);
    void fatal(std::string_view msg);

    /// Generic log call.
    void log(LogLevel level, std::string_view msg);

    // ── Accessors ──────────────────────────────────────────────────────────
    [[nodiscard]] bool     isOpen()      const noexcept;
    [[nodiscard]] LogLevel minLevel()    const noexcept;
    void                   setMinLevel(LogLevel level) noexcept;

private:
    Logger() = default;
    ~Logger();

    // ── Internal helpers ───────────────────────────────────────────────────
    void        rotateIfNeeded();
    void        rotate();
    std::string currentTimestamp() const;
    [[nodiscard]] std::filesystem::path logFilePath(std::size_t index) const;

    // ── State ──────────────────────────────────────────────────────────────
    mutable std::mutex          mutex_;
    std::ofstream               stream_;
    std::filesystem::path       logDir_;
    std::string                 filePrefix_;
    std::size_t                 maxFileSize_ = 0;
    std::size_t                 maxFiles_    = 0;
    LogLevel                    minLevel_    = LogLevel::INFO;
    std::size_t                 currentSize_ = 0;
    bool                        initialised_ = false;
};

// ── Convenience macros (optional) ──────────────────────────────────────────
// Prefer the method calls; macros are provided for quick prototyping only.
#define FIKCER_LOG_INFO(msg)  ::fikcer::utils::Logger::instance().info(msg)
#define FIKCER_LOG_WARN(msg)  ::fikcer::utils::Logger::instance().warn(msg)
#define FIKCER_LOG_ERROR(msg) ::fikcer::utils::Logger::instance().error(msg)

} // namespace fikcer::utils

// ============================================================================
// FikcerAgent – Logger Implementation
// ============================================================================
#include "utils/logger.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace fikcer::utils {

// ── Singleton ──────────────────────────────────────────────────────────────
Logger& Logger::instance() noexcept {
    static Logger inst;          // Meyers singleton – thread-safe in C++11+
    return inst;
}

Logger::~Logger() {
    shutdown();
}

// ── Initialization ─────────────────────────────────────────────────────────
bool Logger::init(const std::filesystem::path& logDir,
                  std::string_view             filePrefix,
                  std::size_t                  maxFileSize,
                  std::size_t                  maxFiles,
                  LogLevel                     minLevel) {
    std::lock_guard lock(mutex_);

    if (initialised_) {
        return true;   // Already running – call shutdown() first to re-init.
    }

    logDir_      = logDir;
    filePrefix_  = filePrefix;
    maxFileSize_ = maxFileSize;
    maxFiles_    = maxFiles;
    minLevel_    = minLevel;

    // Ensure directory tree exists.
    std::error_code ec;
    std::filesystem::create_directories(logDir_, ec);
    if (ec) {
        std::cerr << "[Logger] Failed to create log directory: "
                  << ec.message() << '\n';
        return false;
    }

    // Open the current (index-0) log file in append mode.
    stream_.open(logFilePath(0), std::ios::app | std::ios::ate);
    if (!stream_.is_open()) {
        std::cerr << "[Logger] Failed to open log file.\n";
        return false;
    }

    currentSize_ = static_cast<std::size_t>(stream_.tellp());
    initialised_ = true;
    return true;
}

void Logger::shutdown() {
    std::lock_guard lock(mutex_);
    if (stream_.is_open()) {
        stream_.flush();
        stream_.close();
    }
    initialised_ = false;
}

// ── Public logging shortcuts ───────────────────────────────────────────────
void Logger::trace(std::string_view msg) { log(LogLevel::TRACE, msg); }
void Logger::debug(std::string_view msg) { log(LogLevel::DEBUG, msg); }
void Logger::info (std::string_view msg) { log(LogLevel::INFO,  msg); }
void Logger::warn (std::string_view msg) { log(LogLevel::WARN,  msg); }
void Logger::error(std::string_view msg) { log(LogLevel::ERR,   msg); }
void Logger::fatal(std::string_view msg) { log(LogLevel::FATAL, msg); }

// ── Core log function ──────────────────────────────────────────────────────
void Logger::log(LogLevel level, std::string_view msg) {
    // Fast-reject: compare underlying integer to avoid lock.
    if (static_cast<std::uint8_t>(level) <
        static_cast<std::uint8_t>(minLevel_)) {
        return;
    }

    std::lock_guard lock(mutex_);

    if (!initialised_ || !stream_.is_open()) {
        // Fallback to stderr if the logger was not initialised.
        std::cerr << "[" << logLevelTag(level) << "] " << msg << '\n';
        return;
    }

    // Format: [2026-03-02 14:05:07.123] [INFO ] Message text
    std::string line;
    line.reserve(128);
    line += '[';
    line += currentTimestamp();
    line += "] [";
    line += logLevelTag(level);
    line += "] ";
    line += msg;
    line += '\n';

    stream_ << line;
    stream_.flush();                    // Ensure durability per entry.
    currentSize_ += line.size();

    rotateIfNeeded();
}

// ── Accessors ──────────────────────────────────────────────────────────────
bool Logger::isOpen() const noexcept {
    std::lock_guard lock(mutex_);
    return initialised_ && stream_.is_open();
}

LogLevel Logger::minLevel() const noexcept {
    return minLevel_;              // Atomic-width read – safe without lock.
}

void Logger::setMinLevel(LogLevel level) noexcept {
    minLevel_ = level;
}

// ── Internal helpers ───────────────────────────────────────────────────────

std::string Logger::currentTimestamp() const {
    using namespace std::chrono;

    const auto now   = system_clock::now();
    const auto ms    = duration_cast<milliseconds>(
                           now.time_since_epoch()) % 1000;
    const auto timer = system_clock::to_time_t(now);

    std::tm bt{};
#if defined(_WIN32)
    localtime_s(&bt, &timer);           // Thread-safe on Windows.
#else
    localtime_r(&timer, &bt);           // Thread-safe on POSIX.
#endif

    std::ostringstream oss;
    oss << std::put_time(&bt, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::filesystem::path Logger::logFilePath(std::size_t index) const {
    // index 0  → fikcerAgent.log
    // index 1  → fikcerAgent.1.log
    // index N  → fikcerAgent.N.log
    std::string name = filePrefix_;
    if (index > 0) {
        name += '.' + std::to_string(index);
    }
    name += ".log";
    return logDir_ / name;
}

void Logger::rotateIfNeeded() {
    if (currentSize_ < maxFileSize_) {
        return;
    }
    rotate();
}

void Logger::rotate() {
    // Close the current file.
    stream_.close();

    // Shift existing rotated files:  N-1 → N, … , 1 → 2, 0 → 1.
    // Delete the oldest if we're at the cap.
    std::error_code ec;
    for (std::size_t i = maxFiles_; i >= 1; --i) {
        auto src = logFilePath(i - 1);
        auto dst = logFilePath(i);

        if (i == maxFiles_) {
            // Remove the oldest rotated file.
            std::filesystem::remove(dst, ec);
        }
        if (std::filesystem::exists(src, ec)) {
            std::filesystem::rename(src, dst, ec);
        }
    }

    // Open a fresh index-0 file.
    stream_.open(logFilePath(0), std::ios::trunc);
    currentSize_ = 0;

    if (!stream_.is_open()) {
        std::cerr << "[Logger] Failed to open new log file after rotation.\n";
        initialised_ = false;
    }
}

} // namespace fikcer::utils

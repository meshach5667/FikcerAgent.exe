/**
 * @file logger.cpp
 * @brief Implementation of the thread-safe rotating file logger.
 *
 * FikcerAgent – Autonomous Self-Healing System Agent
 * Module: Utils / Logger
 *
 * Design decisions:
 *   - A single std::mutex protects all mutable state.  The lock is held
 *     only for the duration of one Log() call, keeping contention low.
 *   - Timestamps use <chrono> (no C-runtime localtime_s dependency).
 *   - Log rotation is size-based: when the current file exceeds the
 *     threshold a new file is created with a fresh timestamp in the name.
 */

#include "logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace fikcer::utils {

// --------------------------------------------------------------------------
// Singleton
// --------------------------------------------------------------------------
Logger& Logger::Instance() noexcept {
    static Logger instance;          // Meyers' singleton – thread-safe in C++11+.
    return instance;
}

Logger::~Logger() {
    Shutdown();
}

// --------------------------------------------------------------------------
// Init / Shutdown
// --------------------------------------------------------------------------
bool Logger::Init(const std::filesystem::path& log_directory,
                  std::size_t max_file_bytes,
                  LogLevel min_level,
                  bool echo_stderr) {
    std::lock_guard lock(mutex_);

    if (initialised_) {
        return true;  // Already initialised – idempotent.
    }

    // Validate and create directory.
    std::error_code ec;
    std::filesystem::create_directories(log_directory, ec);
    if (ec) {
        std::cerr << "[Logger] Failed to create log directory: "
                  << log_directory << " (" << ec.message() << ")\n";
        return false;
    }

    log_dir_        = log_directory;
    max_file_bytes_ = (max_file_bytes > 0) ? max_file_bytes : (5 * 1024 * 1024);
    min_level_      = min_level;
    echo_stderr_    = echo_stderr;

    if (!OpenNewFile()) {
        return false;
    }

    initialised_ = true;
    return true;
}

void Logger::Shutdown() noexcept {
    std::lock_guard lock(mutex_);
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }
    initialised_ = false;
}

// --------------------------------------------------------------------------
// Core logging
// --------------------------------------------------------------------------
void Logger::Log(LogLevel level, std::string_view message) {
    if (level < min_level_) {
        return;  // Below threshold – skip without locking.
    }

    std::lock_guard lock(mutex_);
    if (!initialised_ || !file_.is_open()) {
        // Fallback: at least print to stderr so nothing is silently lost.
        std::cerr << "[Logger-UNINITIALIZED] " << message << "\n";
        return;
    }

    // Build the formatted line:  [2026-03-02 14:05:23.456] [INFO ] message
    std::string ts   = Timestamp();
    auto        tag  = LogLevelToString(level);

    std::ostringstream line;
    line << ts << " [" << tag << "] " << message << '\n';

    std::string formatted = line.str();

    // Write to file.
    file_ << formatted;
    file_.flush();                          // Ensure durability.
    current_bytes_ += formatted.size();

    // Optionally echo to stderr.
    if (echo_stderr_) {
        std::cerr << formatted;
    }

    // Rotate if the file grew too large.
    RotateIfNeeded();
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------
std::string Logger::Timestamp() {
    using namespace std::chrono;

    auto now    = system_clock::now();
    auto tt     = system_clock::to_time_t(now);
    auto millis = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    std::tm buf{};
#if defined(_WIN32)
    localtime_s(&buf, &tt);
#else
    localtime_r(&tt, &buf);
#endif

    std::ostringstream oss;
    oss << '[' << std::put_time(&buf, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << millis.count() << ']';
    return oss.str();
}

std::filesystem::path Logger::MakeLogFilePath() const {
    using namespace std::chrono;

    auto now = system_clock::now();
    auto tt  = system_clock::to_time_t(now);

    std::tm buf{};
#if defined(_WIN32)
    localtime_s(&buf, &tt);
#else
    localtime_r(&tt, &buf);
#endif

    std::ostringstream name;
    name << "fikcer_" << std::put_time(&buf, "%Y%m%d_%H%M%S") << ".log";
    return log_dir_ / name.str();
}

bool Logger::OpenNewFile() {
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }

    auto path = MakeLogFilePath();
    file_.open(path, std::ios::out | std::ios::app);
    if (!file_.is_open()) {
        std::cerr << "[Logger] Failed to open log file: " << path << "\n";
        return false;
    }

    current_bytes_ = 0;
    return true;
}

void Logger::RotateIfNeeded() {
    if (current_bytes_ >= max_file_bytes_) {
        OpenNewFile();
    }
}

}  // namespace fikcer::utils

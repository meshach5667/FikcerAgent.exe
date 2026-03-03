// ============================================================================
// FikcerAgent – Shell Command Execution Utility
// ============================================================================
#pragma once

#include <array>
#include <cstdio>
#include <memory>
#include <string>

namespace fikcer::utils {

/// Run a shell command and capture its stdout.
/// Returns empty string on failure.  Timeout is best-effort (not enforced here).
inline std::string exec(const std::string& cmd) {
    std::array<char, 4096> buffer{};
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(
        popen(cmd.c_str(), "r"), pclose);

    if (!pipe) return "";

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get())) {
        result += buffer.data();
    }
    return result;
}

/// Run a command and return its exit code.  stdout is discarded.
inline int execStatus(const std::string& cmd) {
    std::string silent = cmd + " >/dev/null 2>&1";
    return system(silent.c_str());
}

} // namespace fikcer::utils

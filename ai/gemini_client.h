// ============================================================================
// FikcerAgent – Gemini API Client Interface
// ============================================================================
// HTTP client for Google Gemini generative AI API.
//
// Usage:
//   GeminiClient client;
//   if (client.init()) {
//       auto response = client.ask("Analyse this system data: ...");
//       // response contains Gemini's text reply
//   }
//
// API key resolution order:
//   1. Environment variable  FIKCER_GEMINI_API_KEY
//   2. File                  ~/.fikcerAgent/gemini_api_key
//   3. Empty → Gemini features disabled (fallback to heuristic)
// ============================================================================
#pragma once

#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace fikcer::ai {

// ── Parsed problem from Gemini response ────────────────────────────────────

struct GeminiProblem {
    std::string type;           // DISK_SPACE, MALWARE, NETWORK, etc.
    std::string severity;       // LOW, MEDIUM, HIGH, CRITICAL
    std::string description;    // Human-readable description
    std::string fixType;        // COMMAND, KILL, PURGE, NONE
    std::string fixTarget;      // Shell command, PID, or empty
    std::string fixDescription; // What the fix does
};

// ── Gemini Client ──────────────────────────────────────────────────────────

class GeminiClient final {
public:
    GeminiClient();
    ~GeminiClient();

    GeminiClient(const GeminiClient&) = delete;
    GeminiClient& operator=(const GeminiClient&) = delete;

    /// Initialise the client.  Returns true if an API key was found.
    [[nodiscard]] bool init();

    /// @return true if the client has a valid API key and is ready.
    [[nodiscard]] bool isAvailable() const noexcept;

    /// Send a prompt to Gemini and get the raw text response.
    /// Returns empty string on failure.
    [[nodiscard]] std::string ask(const std::string& prompt);

    /// Send system diagnostics to Gemini and get structured problems back.
    [[nodiscard]] std::vector<GeminiProblem> analyseSystem(
        const std::string& systemReport);

    /// Get the last error message (for diagnostics).
    [[nodiscard]] std::string lastError() const;

    /// Get the model name in use.
    [[nodiscard]] std::string modelName() const;

private:
    // ── Helpers ────────────────────────────────────────────────────────────
    [[nodiscard]] std::string loadApiKey() const;
    [[nodiscard]] std::string buildRequestJson(const std::string& prompt) const;
    [[nodiscard]] static std::string extractTextFromResponse(const std::string& json);
    [[nodiscard]] static std::string escapeJson(const std::string& s);
    [[nodiscard]] std::vector<GeminiProblem> parseProblems(const std::string& text) const;

    /// Perform HTTP POST via libcurl.
    [[nodiscard]] std::string httpPost(const std::string& url,
                                       const std::string& jsonBody);

    // ── State ──────────────────────────────────────────────────────────────
    std::string apiKey_;
    std::string model_;
    std::string lastError_;
    mutable std::mutex mutex_;
    bool available_ = false;
};

} // namespace fikcer::ai

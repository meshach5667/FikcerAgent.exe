// ============================================================================
// FikcerAgent – Gemini API Client Implementation
// ============================================================================
#include "ai/gemini_client.h"
#include "utils/logger.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <curl/curl.h>

namespace fikcer::ai {

using utils::Logger;

// ── libcurl write callback ─────────────────────────────────────────────────

static size_t curlWriteCallback(char* ptr, size_t size, size_t nmemb,
                                void* userdata) {
    auto* buf = static_cast<std::string*>(userdata);
    size_t total = size * nmemb;
    buf->append(ptr, total);
    return total;
}

// ── Construction / Destruction ─────────────────────────────────────────────

GeminiClient::GeminiClient()
    : model_("gemini-2.0-flash")
{}

GeminiClient::~GeminiClient() = default;

// ── Initialisation ─────────────────────────────────────────────────────────

bool GeminiClient::init() {
    std::lock_guard lock(mutex_);

    apiKey_ = loadApiKey();
    if (apiKey_.empty()) {
        lastError_ = "No API key found.  "
                     "Create ~/.fikcerAgent/gemini_api_key";
        available_ = false;
        Logger::instance().warn("AI: " + lastError_);
        return false;
    }

    // Quick validation: key should be non-trivial.
    if (apiKey_.size() < 10) {
        lastError_ = "API key looks invalid (too short).";
        available_ = false;
        Logger::instance().warn("AI: " + lastError_);
        return false;
    }

    available_ = true;
    Logger::instance().info("AI initialised with model: " + model_);
    return true;
}

bool GeminiClient::isAvailable() const noexcept {
    return available_;
}

std::string GeminiClient::lastError() const {
    std::lock_guard lock(mutex_);
    return lastError_;
}

std::string GeminiClient::modelName() const {
    return model_;
}

// ── API Key Loading ────────────────────────────────────────────────────────

std::string GeminiClient::loadApiKey() const {
    // 1. Environment variable.
    const char* envKey = std::getenv("FIKCER_GEMINI_API_KEY");
    if (envKey && std::strlen(envKey) > 0) {
        Logger::instance().info(" API key loaded from environment variable.");
        return std::string(envKey);
    }

    // 2. Config file.
    std::filesystem::path home;
#ifdef _WIN32
    const char* userProfile = std::getenv("USERPROFILE");
    if (userProfile) home = userProfile;
#else
    const char* homeEnv = std::getenv("HOME");
    if (homeEnv) home = homeEnv;
#endif

    if (!home.empty()) {
        auto keyFile = home / ".fikcerAgent" / "gemini_api_key";
        if (std::filesystem::exists(keyFile)) {
            std::ifstream ifs(keyFile);
            std::string key;
            if (std::getline(ifs, key)) {
                // Trim whitespace.
                key.erase(0, key.find_first_not_of(" \t\r\n"));
                key.erase(key.find_last_not_of(" \t\r\n") + 1);
                if (!key.empty()) {
                    Logger::instance().info(
                        " API key loaded from " + keyFile.string());
                    return key;
                }
            }
        }
    }

    // 3. .env file in the working directory.
    std::filesystem::path envFile = ".env";
    if (std::filesystem::exists(envFile)) {
        std::ifstream ifs(envFile);
        std::string line;
        while (std::getline(ifs, line)) {
            line.erase(0, line.find_first_not_of(" \t"));
            if (line.empty() || line[0] == '#') continue;

            auto eqPos = line.find('=');
            if (eqPos == std::string::npos) continue;

            std::string key = line.substr(0, eqPos);
            std::string val = line.substr(eqPos + 1);

            // Strip surrounding quotes (' or ").
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t\r\n") + 1);
            if (val.size() >= 2) {
                if ((val.front() == '\'' && val.back() == '\'') ||
                    (val.front() == '"'  && val.back() == '"')) {
                    val = val.substr(1, val.size() - 2);
                }
            }

            if (key == "FIKCER_GEMINI_API_KEY" && !val.empty()) {
                Logger::instance().info("Gemini API key loaded from .env file.");
                return val;
            }
        }
    }

    return "";
}

// ── JSON Helpers ───────────────────────────────────────────────────────────

std::string GeminiClient::escapeJson(const std::string& s) {
    std::string result;
    result.reserve(s.size() + s.size() / 8);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            case '\b': result += "\\b";  break;
            case '\f': result += "\\f";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned int>(c));
                    result += buf;
                } else {
                    result += c;
                }
        }
    }
    return result;
}

std::string GeminiClient::buildRequestJson(const std::string& prompt) const {
    std::ostringstream oss;
    oss << R"({"contents":[{"parts":[{"text":")"
        << escapeJson(prompt)
        << R"("}]}],"generationConfig":{"temperature":0.1,"maxOutputTokens":4096}})";
    return oss.str();
}

std::string GeminiClient::extractTextFromResponse(const std::string& json) {
    // Gemini response format:
    // {"candidates":[{"content":{"parts":[{"text":"..."}],...},...}]}
    // We need to find the "text" field value inside parts.

    // Find the first "text" field after "parts".
    auto partsPos = json.find("\"parts\"");
    if (partsPos == std::string::npos) return "";

    auto textPos = json.find("\"text\"", partsPos);
    if (textPos == std::string::npos) return "";

    // Find the colon after "text"
    auto colonPos = json.find(':', textPos + 6);
    if (colonPos == std::string::npos) return "";

    // Find opening quote of the value.
    auto openQuote = json.find('"', colonPos + 1);
    if (openQuote == std::string::npos) return "";
    openQuote++; // Skip the quote itself.

    // Read until unescaped closing quote, handling escape sequences.
    std::string text;
    text.reserve(json.size() - openQuote);
    size_t pos = openQuote;

    while (pos < json.size()) {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            char next = json[pos + 1];
            switch (next) {
                case '"':  text += '"';  break;
                case '\\': text += '\\'; break;
                case 'n':  text += '\n'; break;
                case 'r':  text += '\r'; break;
                case 't':  text += '\t'; break;
                case '/':  text += '/';  break;
                default:   text += next; break;
            }
            pos += 2;
        } else if (json[pos] == '"') {
            break;
        } else {
            text += json[pos];
            pos++;
        }
    }

    return text;
}

// ── HTTP POST via libcurl ──────────────────────────────────────────────────

std::string GeminiClient::httpPost(const std::string& url,
                                    const std::string& jsonBody) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        lastError_ = "Failed to initialise libcurl.";
        return "";
    }

    std::string responseBody;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(jsonBody.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);        // 30s timeout
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);  // 10s connect
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        lastError_ = std::string("HTTP request failed: ") +
                     curl_easy_strerror(res);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return "";
    }

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (httpCode != 200) {
        lastError_ = "HTTP " + std::to_string(httpCode) + ": " + responseBody;
        Logger::instance().error("Gemini API error: " + lastError_);
        return "";
    }

    return responseBody;
}

// ── Core API Methods ───────────────────────────────────────────────────────

std::string GeminiClient::ask(const std::string& prompt) {
    if (!available_) {
        lastError_ = "AI client not initialised.";
        return "";
    }

    std::string url =
        "https://generativelanguage.googleapis.com/v1beta/models/" +
        model_ + ":generateContent?key=" + apiKey_;

    std::string reqBody = buildRequestJson(prompt);
    std::string response = httpPost(url, reqBody);

    if (response.empty()) return "";

    std::string text = extractTextFromResponse(response);
    if (text.empty()) {
        lastError_ = "Failed to parse Gemini response.";
        Logger::instance().warn("AI: empty text in response.");
    }

    return text;
}

// ── System Analysis ────────────────────────────────────────────────────────

std::vector<GeminiProblem> GeminiClient::analyseSystem(
    const std::string& systemReport)
{
    std::string prompt =
        "You are FikcerAgent, an autonomous system healing AI agent running "
        "on the user's computer. Your job is to analyze system diagnostics "
        "and identify ALL real problems that need fixing.\n\n"
        "IMPORTANT RULES:\n"
        "- Only report REAL problems. Don't report healthy metrics as issues.\n"
        "- Be specific about what's wrong and how to fix it.\n"
        "- For commands, use the correct OS commands (check OS in report).\n"
        "- For KILL actions, provide the actual PID number.\n"
        "- Only suggest safe fixes. Never suggest destructive commands.\n"
        "- If everything looks healthy, respond with: NO_PROBLEMS_DETECTED\n\n"
        "SYSTEM DIAGNOSTICS:\n" + systemReport + "\n\n"
        "For EACH problem found, respond in EXACTLY this pipe-delimited format "
        "(one problem per line):\n"
        "PROBLEM|<TYPE>|<SEVERITY>|<DESCRIPTION>|<FIX_TYPE>|<FIX_TARGET>|<FIX_DESC>\n\n"
        "Where:\n"
        "- TYPE: DISK_SPACE, DISK_HEALTH, NETWORK, DNS, MALWARE, MEMORY, CPU, "
        "TEMPERATURE, BATTERY, DRIVER, INTEGRITY, STARTUP, OTHER\n"
        "- SEVERITY: LOW, MEDIUM, HIGH, CRITICAL\n"
        "- FIX_TYPE: COMMAND (shell command), KILL (process PID), "
        "PURGE (clear memory), NONE (no auto-fix)\n"
        "- FIX_TARGET: the shell command, PID number, or empty\n\n"
        "Examples:\n"
        "PROBLEM|DISK_SPACE|HIGH|Root partition 92% full with only 8GB free|"
        "COMMAND|rm -rf ~/Library/Caches/* /tmp/*.tmp|Clear caches to free space\n"
        "PROBLEM|MALWARE|CRITICAL|Suspicious process xmrig detected (crypto miner)|"
        "KILL|9999|Terminate cryptocurrency miner\n"
        "PROBLEM|DNS|MEDIUM|DNS resolution taking 800ms|"
        "COMMAND|sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder|"
        "Flush DNS cache\n";

    Logger::instance().info("Sending system report to AI for analysis...");

    std::string response = ask(prompt);
    if (response.empty()) {
        Logger::instance().warn("AI returned empty response.");
        return {};
    }

    Logger::instance().debug("AI response: " + response.substr(0, 200));

    return parseProblems(response);
}

// ── Parse Gemini Response ──────────────────────────────────────────────────

std::vector<GeminiProblem> GeminiClient::parseProblems(
    const std::string& text) const
{
    std::vector<GeminiProblem> problems;

    if (text.find("NO_PROBLEMS_DETECTED") != std::string::npos) {
        Logger::instance().info("AI: No problems detected. System healthy.");
        return problems;
    }

    std::istringstream stream(text);
    std::string line;

    while (std::getline(stream, line)) {
        // Trim.
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.substr(0, 8) != "PROBLEM|") continue;

        // Split by pipe.
        std::vector<std::string> parts;
        std::istringstream pipeStream(line);
        std::string part;
        while (std::getline(pipeStream, part, '|')) {
            parts.push_back(part);
        }

        // Expect at least 7 fields: PROBLEM|TYPE|SEV|DESC|FIX_TYPE|TARGET|FIX_DESC
        if (parts.size() < 7) continue;

        GeminiProblem p;
        p.type           = parts[1];
        p.severity       = parts[2];
        p.description    = parts[3];
        p.fixType        = parts[4];
        p.fixTarget      = parts[5];
        p.fixDescription = parts[6];

        // Validate severity.
        if (p.severity != "LOW" && p.severity != "MEDIUM" &&
            p.severity != "HIGH" && p.severity != "CRITICAL") {
            p.severity = "MEDIUM"; // Default if Gemini gives unexpected value.
        }

        Logger::instance().info("Gemini detected: [" + p.severity + "] " +
                                p.type + " - " + p.description);

        problems.push_back(std::move(p));
    }

    return problems;
}

} // namespace fikcer::ai

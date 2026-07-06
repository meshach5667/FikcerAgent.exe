// ============================================================================
// FikcerAgent – AI Planning Engine Implementation
// ============================================================================
#include "agent/ai_planner.h"
#include "utils/logger.h"

#include <algorithm>
#include <sstream>

namespace fikcer::agent {

using utils::Logger;

AiPlanner::AiPlanner() = default;

// ── Plan generation ────────────────────────────────────────────────────────

std::vector<ActionPlan> AiPlanner::plan(
    ai::GeminiClient& gemini,
    const WorldState& state,
    const std::vector<Goal>& unsatisfiedGoals,
    const MemoryStore& memory,
    const ToolRegistry& tools)
{
    if (!gemini.isAvailable()) {
        auto reason = gemini.lastError();
        if (reason.empty()) {
            reason = "no API key configured";
        }
        Logger::instance().warn(std::string("AiPlanner: Gemini not available (") +
                                reason + "), skipping.");
        return {};
    }

    // Build the prompt.
    std::string prompt = buildPrompt(state, unsatisfiedGoals, memory, tools);
    {
        std::lock_guard lock(mutex_);
        lastPrompt_ = prompt;
    }

    // Ask Gemini for structured JSON response.
    std::string response = gemini.ask(prompt, true);
    {
        std::lock_guard lock(mutex_);
        lastResponse_ = response;
    }

    if (response.empty()) {
        auto reason = gemini.lastError();
        std::string suffix = reason.empty() ? std::string() : std::string(" (") + reason + ")";
        Logger::instance().warn(std::string("AiPlanner: empty response from Gemini") + suffix);
        return {};
    }

    // Check for "no problems" sentinel.
    if (response.find("NO_ISSUES") != std::string::npos ||
        response.find("no_issues") != std::string::npos ||
        response.find("\"plans\": []") != std::string::npos ||
        response.find("\"plans\":[]") != std::string::npos) {
        Logger::instance().info("AiPlanner: Gemini says no issues.");
        return {};
    }

    // Parse plans.
    auto plans = parsePlans(response);

    // Validate each plan against the tool registry.
    for (auto& p : plans) {
        validatePlan(p, tools);
    }

    // Remove invalid plans.
    plans.erase(
        std::remove_if(plans.begin(), plans.end(),
                       [](const ActionPlan& p) { return !p.valid; }),
        plans.end());

    // Sort by severity (critical first).
    std::sort(plans.begin(), plans.end(),
              [](const ActionPlan& a, const ActionPlan& b) {
                  auto sevRank = [](const std::string& s) {
                      if (s == "critical") return 3;
                      if (s == "high") return 2;
                      if (s == "medium") return 1;
                      return 0;
                  };
                  return sevRank(a.severity) > sevRank(b.severity);
              });

    Logger::instance().info("AiPlanner: " + std::to_string(plans.size()) +
                            " action plan(s) generated.");
    return plans;
}

// ── Prompt building ────────────────────────────────────────────────────────

std::string AiPlanner::buildPrompt(
    const WorldState& state,
    const std::vector<Goal>& unsatisfiedGoals,
    const MemoryStore& memory,
    const ToolRegistry& tools) const
{
    std::ostringstream p;

    p << "You are FikcerAgent, an autonomous AI system health and security agent. "
         "You continuously monitor and protect a user's computer.\n\n";

    p << "INSTRUCTIONS:\n"
         "- Analyze the system state below.\n"
         "- Identify any issues that need corrective action.\n"
         "- For each issue, recommend ONE specific tool from the available tools list.\n"
         "- Only recommend tools that are in the available list.\n"
            "- Use the skills and tools catalog below to choose the right capability.\n"
         "- Consider historical action success rates when choosing tools.\n"
         "- Respect user preferences (never do something the user has blocked).\n"
         "- If everything is healthy, respond with: {\"plans\": []}\n\n";

    p << "RESPOND WITH VALID JSON in this exact format:\n"
         "{\n"
         "  \"plans\": [\n"
         "    {\n"
         "      \"issue\": \"<problem_description>\",\n"
         "      \"root_cause\": \"<root_cause_analysis>\",\n"
         "      \"severity\": \"<low|medium|high|critical>\",\n"
         "      \"recommended_action\": \"<ToolName from available tools>\",\n"
         "      \"parameters\": {\"<param_name>\": \"<param_value>\"},\n"
         "      \"confidence\": <0.0-1.0>,\n"
         "      \"risk_level\": \"<low|medium|high>\",\n"
         "      \"requires_user_approval\": <true|false>,\n"
         "      \"reasoning\": \"<explanation>\"\n"
         "    }\n"
         "  ]\n"
         "}\n\n";

    // World state.
    p << "CURRENT SYSTEM STATE:\n" << state.toJson() << "\n\n";

    // Unsatisfied goals.
    if (!unsatisfiedGoals.empty()) {
        p << "UNSATISFIED GOALS:\n";
        for (const auto& g : unsatisfiedGoals) {
            p << "  - " << g.name << " (current: " << g.currentValue
              << ", target: " << g.targetValue
              << ", priority: " << goalPriorityTag(g.effectivePriority) << ")\n";
        }
        p << "\n";
    }

    // Historical data.
    p << memory.actionStatsForPlanner() << "\n";
    p << memory.incidentHistoryForPlanner(5) << "\n";
    p << memory.preferencesForPlanner() << "\n";

    // Available tools.
    p << tools.toolsForPlanner();

    return p.str();
}

// ── Plan validation ────────────────────────────────────────────────────────

bool AiPlanner::validatePlan(ActionPlan& plan, const ToolRegistry& tools) const {
    if (plan.recommendedAction.empty()) {
        plan.valid = false;
        return false;
    }

    const Tool* tool = tools.findTool(plan.recommendedAction);
    if (!tool) {
        Logger::instance().warn("AiPlanner: unknown tool '" +
                                 plan.recommendedAction + "'");
        plan.valid = false;
        return false;
    }

    plan.valid = true;
    return true;
}

// ── JSON Parsing Helpers ───────────────────────────────────────────────────

// Minimal JSON value extractor (finds "key": "value" or "key": number).
static std::string extractJsonString(const std::string& json,
                                      const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";

    // Find the colon.
    auto colon = json.find(':', pos + needle.size());
    if (colon == std::string::npos) return "";

    // Skip whitespace.
    auto start = json.find_first_not_of(" \t\r\n", colon + 1);
    if (start == std::string::npos) return "";

    if (json[start] == '"') {
        // String value — read until unescaped closing quote.
        start++;
        std::string val;
        for (size_t i = start; i < json.size(); ++i) {
            if (json[i] == '\\' && i + 1 < json.size()) {
                val += json[i + 1];
                ++i;
            } else if (json[i] == '"') {
                break;
            } else {
                val += json[i];
            }
        }
        return val;
    }

    // Numeric or boolean — read until comma, brace, or bracket.
    auto end = json.find_first_of(",}] \t\r\n", start);
    if (end == std::string::npos) end = json.size();
    return json.substr(start, end - start);
}

static double extractJsonDouble(const std::string& json, const std::string& key) {
    std::string val = extractJsonString(json, key);
    try { return std::stod(val); } catch (...) { return 0.0; }
}

static bool extractJsonBool(const std::string& json, const std::string& key) {
    std::string val = extractJsonString(json, key);
    return val == "true";
}

// Extract a simple {"key": "value", ...} object as ToolParams.
static ToolParams extractJsonParams(const std::string& json,
                                     const std::string& key) {
    ToolParams params;
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return params;

    auto braceStart = json.find('{', pos);
    if (braceStart == std::string::npos) return params;

    // Find matching closing brace.
    int depth = 0;
    size_t braceEnd = braceStart;
    for (size_t i = braceStart; i < json.size(); ++i) {
        if (json[i] == '{') depth++;
        else if (json[i] == '}') {
            depth--;
            if (depth == 0) { braceEnd = i; break; }
        }
    }

    std::string obj = json.substr(braceStart, braceEnd - braceStart + 1);

    // Parse simple key-value pairs.
    size_t searchPos = 0;
    while (true) {
        auto kStart = obj.find('"', searchPos);
        if (kStart == std::string::npos) break;
        auto kEnd = obj.find('"', kStart + 1);
        if (kEnd == std::string::npos) break;
        std::string k = obj.substr(kStart + 1, kEnd - kStart - 1);

        auto vStart = obj.find('"', kEnd + 2);  // Skip ":"
        if (vStart == std::string::npos) break;
        auto vEnd = obj.find('"', vStart + 1);
        if (vEnd == std::string::npos) break;
        std::string v = obj.substr(vStart + 1, vEnd - vStart - 1);

        params[k] = v;
        searchPos = vEnd + 1;
    }

    return params;
}

ActionPlan AiPlanner::parsePlan(const std::string& json) {
    ActionPlan plan;

    plan.issue = extractJsonString(json, "issue");
    plan.rootCause = extractJsonString(json, "root_cause");
    plan.severity = extractJsonString(json, "severity");
    plan.recommendedAction = extractJsonString(json, "recommended_action");
    plan.parameters = extractJsonParams(json, "parameters");
    plan.confidence = extractJsonDouble(json, "confidence");
    plan.riskLevel = extractJsonString(json, "risk_level");
    plan.requiresApproval = extractJsonBool(json, "requires_user_approval");
    plan.reasoning = extractJsonString(json, "reasoning");

    plan.valid = !plan.issue.empty() && !plan.recommendedAction.empty();
    return plan;
}

std::vector<ActionPlan> AiPlanner::parsePlans(const std::string& json) {
    std::vector<ActionPlan> plans;

    // Find the "plans" array.
    auto plansPos = json.find("\"plans\"");
    if (plansPos == std::string::npos) {
        // Try parsing as a single plan object.
        auto plan = parsePlan(json);
        if (plan.valid) plans.push_back(std::move(plan));
        return plans;
    }

    // Find each object in the plans array.
    auto arrStart = json.find('[', plansPos);
    if (arrStart == std::string::npos) return plans;

    size_t pos = arrStart + 1;
    while (pos < json.size()) {
        auto objStart = json.find('{', pos);
        if (objStart == std::string::npos) break;

        // Find matching closing brace.
        int depth = 0;
        size_t objEnd = objStart;
        for (size_t i = objStart; i < json.size(); ++i) {
            if (json[i] == '{') depth++;
            else if (json[i] == '}') {
                depth--;
                if (depth == 0) { objEnd = i; break; }
            }
        }

        std::string objStr = json.substr(objStart, objEnd - objStart + 1);
        auto plan = parsePlan(objStr);
        if (plan.valid) {
            plans.push_back(std::move(plan));
        }

        pos = objEnd + 1;
    }

    return plans;
}

std::string AiPlanner::lastPrompt() const {
    std::lock_guard lock(mutex_);
    return lastPrompt_;
}

std::string AiPlanner::lastResponse() const {
    std::lock_guard lock(mutex_);
    return lastResponse_;
}

} // namespace fikcer::agent

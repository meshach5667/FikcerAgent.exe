// ============================================================================
// FikcerAgent – Approved Tool Registry
// ============================================================================
// The AI agent may only invoke pre-registered tools.  No arbitrary shell
// commands are allowed.  Each tool has:
//
//   • A unique name (e.g., "RestartProcess")
//   • A category (Monitoring, Recovery, Security, Verification)
//   • A risk level (Low, Medium, High)
//   • An execute function that takes named parameters and returns a result
//
// The AI planner references tools by name.  The executor looks up the tool
// in this registry and invokes it.  This is the core safety mechanism.
// ============================================================================
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace fikcer::agent {

// ── Tool enumerations ──────────────────────────────────────────────────────

enum class ToolCategory : uint8_t {
    MONITORING   = 0,
    RECOVERY     = 1,
    SECURITY     = 2,
    VERIFICATION = 3,
};

enum class RiskLevel : uint8_t {
    LOW    = 0,   ///< Auto-execute without user interaction.
    MEDIUM = 1,   ///< Notify user, optionally wait for confirmation.
    HIGH   = 2,   ///< Require explicit user approval before execution.
};

[[nodiscard]] constexpr std::string_view riskLevelTag(RiskLevel r) noexcept {
    switch (r) {
        case RiskLevel::LOW:    return "LOW";
        case RiskLevel::MEDIUM: return "MEDIUM";
        case RiskLevel::HIGH:   return "HIGH";
    }
    return "UNKNOWN";
}

[[nodiscard]] constexpr std::string_view toolCategoryTag(ToolCategory c) noexcept {
    switch (c) {
        case ToolCategory::MONITORING:   return "MONITORING";
        case ToolCategory::RECOVERY:     return "RECOVERY";
        case ToolCategory::SECURITY:     return "SECURITY";
        case ToolCategory::VERIFICATION: return "VERIFICATION";
    }
    return "UNKNOWN";
}

// ── Tool parameters and results ────────────────────────────────────────────

/// Named parameters passed to a tool.
using ToolParams = std::map<std::string, std::string>;

/// Result of executing a tool.
struct ToolResult {
    bool        success = false;
    std::string output;         ///< Human-readable output or data.
    std::string error;          ///< Error message if !success.
    double      metricValue = 0.0; ///< Optional numeric result (e.g., CPU %).
};

/// Tool execution function signature.
using ToolExecutor = std::function<ToolResult(const ToolParams&)>;

// ── Tool definition ────────────────────────────────────────────────────────

struct Tool {
    std::string   name;             ///< Unique tool name (e.g., "RestartProcess").
    std::string   description;      ///< What this tool does.
    ToolCategory  category;
    RiskLevel     risk;
    bool          requiresApproval; ///< Derived from risk + user preferences.
    std::vector<std::string> parameterNames; ///< Expected parameter names.
    ToolExecutor  executor;         ///< The function that does the work.
};

// ── Tool Registry ──────────────────────────────────────────────────────────

class ToolRegistry final {
public:
    ToolRegistry();
    ~ToolRegistry() = default;

    ToolRegistry(const ToolRegistry&) = delete;
    ToolRegistry& operator=(const ToolRegistry&) = delete;

    /// Register all built-in tools.
    void registerDefaultTools();

    /// Register a custom tool.
    void registerTool(Tool tool);

    /// Look up a tool by name.
    /// @return nullptr if not found.
    [[nodiscard]] const Tool* findTool(const std::string& name) const;

    /// Execute a tool by name with the given parameters.
    /// Returns failure if the tool is not registered.
    [[nodiscard]] ToolResult execute(const std::string& name,
                                     const ToolParams& params);

    /// @return All registered tool names.
    [[nodiscard]] std::vector<std::string> toolNames() const;

    /// @return All tools in a specific category.
    [[nodiscard]] std::vector<const Tool*> toolsByCategory(ToolCategory cat) const;

    /// @return A formatted summary of available tools for the AI planner.
    [[nodiscard]] std::string toolsForPlanner() const;

private:
    void registerToolInternal(Tool tool);

    mutable std::mutex mutex_;
    std::map<std::string, Tool> tools_;
};

} // namespace fikcer::agent

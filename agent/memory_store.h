// ============================================================================
// FikcerAgent – Persistent Memory Store Interface
// ============================================================================
// SQLite-backed persistent memory for the agent.  Stores:
//
//   1. Incident history   – problem, root cause, action, result, timestamp
//   2. Security events    – detections, responses, outcomes
//   3. Action statistics  – per-action success/failure counts
//   4. User preferences   – behavioral rules for the agent
//
// Database location: ~/.fikcerAgent/memory.db
// ============================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// Forward declare sqlite3 to avoid leaking the header.
struct sqlite3;

namespace fikcer::agent {

// ── Data records ───────────────────────────────────────────────────────────

struct IncidentRecord {
    int64_t     id = 0;
    std::string problem;
    std::string rootCause;
    std::string actionTaken;
    std::string result;         ///< "success", "partial", "failure", "regression"
    std::string severity;
    double      healthBefore = 0.0;
    double      healthAfter  = 0.0;
    std::string timestamp;
};

struct SecurityEvent {
    int64_t     id = 0;
    std::string type;           ///< "malware", "firewall", "network_anomaly", "quarantine"
    std::string details;
    std::string actionTaken;
    std::string outcome;
    std::string severity;
    std::string timestamp;
};

struct ActionStats {
    std::string actionName;
    int64_t     totalAttempts = 0;
    int64_t     successes     = 0;
    int64_t     failures      = 0;
    double      successRate   = 0.0;    ///< Computed: successes / totalAttempts.
    std::string lastUsed;               ///< ISO timestamp of last use.
};

struct UserPreference {
    std::string key;            ///< e.g., "never_restart", "ask_before"
    std::string value;          ///< e.g., "payroll_app", "reboot"
    bool        enabled = true;
};

// ── MemoryStore ────────────────────────────────────────────────────────────

class MemoryStore final {
public:
    MemoryStore();
    ~MemoryStore();

    MemoryStore(const MemoryStore&) = delete;
    MemoryStore& operator=(const MemoryStore&) = delete;

    /// Open (or create) the database at the given path.
    /// @return true on success.
    [[nodiscard]] bool open(const std::string& dbPath);

    /// Close the database connection.
    void close();

    /// @return true if the database is open.
    [[nodiscard]] bool isOpen() const noexcept;

    // ── Incident History ───────────────────────────────────────────────────

    /// Record a completed incident.
    bool recordIncident(const IncidentRecord& rec);

    /// Get the N most recent incidents.
    [[nodiscard]] std::vector<IncidentRecord> getRecentIncidents(int limit = 10) const;

    /// Get incidents matching a specific problem type.
    [[nodiscard]] std::vector<IncidentRecord> getIncidentsByProblem(
        const std::string& problem, int limit = 5) const;

    // ── Security Events ────────────────────────────────────────────────────

    /// Record a security event.
    bool recordSecurityEvent(const SecurityEvent& ev);

    /// Get recent security events.
    [[nodiscard]] std::vector<SecurityEvent> getRecentSecurityEvents(int limit = 10) const;

    // ── Action Statistics ──────────────────────────────────────────────────

    /// Update stats for an action (increment success or failure).
    bool updateActionStats(const std::string& actionName, bool success);

    /// Get stats for a specific action.
    [[nodiscard]] std::optional<ActionStats> getActionStats(
        const std::string& actionName) const;

    /// Get all action stats, sorted by success rate descending.
    [[nodiscard]] std::vector<ActionStats> getAllActionStats() const;

    /// Get the success rate for a specific action.
    /// Returns -1.0 if no data exists.
    [[nodiscard]] double getActionSuccessRate(const std::string& actionName) const;

    // ── User Preferences ───────────────────────────────────────────────────

    /// Set a user preference.
    bool setUserPreference(const std::string& key, const std::string& value,
                           bool enabled = true);

    /// Get a specific preference.
    [[nodiscard]] std::optional<UserPreference> getUserPreference(
        const std::string& key) const;

    /// Get all user preferences.
    [[nodiscard]] std::vector<UserPreference> getAllUserPreferences() const;

    /// Remove a user preference.
    bool removeUserPreference(const std::string& key);

    // ── Formatted output for AI ────────────────────────────────────────────

    /// Get a formatted summary of action stats for the AI planner prompt.
    [[nodiscard]] std::string actionStatsForPlanner() const;

    /// Get a formatted summary of recent incidents for the AI planner prompt.
    [[nodiscard]] std::string incidentHistoryForPlanner(int limit = 5) const;

    /// Get a formatted summary of user preferences for the AI planner prompt.
    [[nodiscard]] std::string preferencesForPlanner() const;

private:
    /// Create all tables if they don't exist.
    bool createTables();

    /// Execute a simple SQL statement.
    bool execSql(const std::string& sql);

    sqlite3* db_ = nullptr;
    mutable std::mutex mutex_;
};

} // namespace fikcer::agent

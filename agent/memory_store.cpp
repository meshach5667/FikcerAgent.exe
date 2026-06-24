// ============================================================================
// FikcerAgent – Persistent Memory Store Implementation (SQLite)
// ============================================================================
#include "agent/memory_store.h"
#include "utils/logger.h"

#include <sqlite3.h>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <sstream>

namespace fikcer::agent {

using utils::Logger;

// ── Helper: current ISO timestamp ──────────────────────────────────────────

static std::string nowTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// ── Construction / Destruction ─────────────────────────────────────────────

MemoryStore::MemoryStore() = default;

MemoryStore::~MemoryStore() {
    close();
}

// ── Open / Close ───────────────────────────────────────────────────────────

bool MemoryStore::open(const std::string& dbPath) {
    std::lock_guard lock(mutex_);

    // Ensure parent directory exists.
    auto parent = std::filesystem::path(dbPath).parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }

    int rc = sqlite3_open(dbPath.c_str(), &db_);
    if (rc != SQLITE_OK) {
        Logger::instance().error("MemoryStore: failed to open " + dbPath +
                                 " — " + sqlite3_errmsg(db_));
        db_ = nullptr;
        return false;
    }

    // Enable WAL mode for better concurrency.
    execSql("PRAGMA journal_mode=WAL;");
    execSql("PRAGMA busy_timeout=5000;");

    if (!createTables()) {
        Logger::instance().error("MemoryStore: failed to create tables.");
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    Logger::instance().info("MemoryStore: opened " + dbPath);
    return true;
}

void MemoryStore::close() {
    std::lock_guard lock(mutex_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool MemoryStore::isOpen() const noexcept {
    return db_ != nullptr;
}

// ── Table Creation ─────────────────────────────────────────────────────────

bool MemoryStore::createTables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS incidents (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            problem       TEXT NOT NULL,
            root_cause    TEXT,
            action_taken  TEXT,
            result        TEXT,
            severity      TEXT,
            health_before REAL,
            health_after  REAL,
            timestamp     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            type          TEXT NOT NULL,
            details       TEXT,
            action_taken  TEXT,
            outcome       TEXT,
            severity      TEXT,
            timestamp     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS action_stats (
            action_name   TEXT PRIMARY KEY,
            total_attempts INTEGER DEFAULT 0,
            successes     INTEGER DEFAULT 0,
            failures      INTEGER DEFAULT 0,
            last_used     TEXT
        );

        CREATE TABLE IF NOT EXISTS user_preferences (
            key           TEXT PRIMARY KEY,
            value         TEXT,
            enabled       INTEGER DEFAULT 1
        );
    )";
    return execSql(sql);
}

bool MemoryStore::execSql(const std::string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::string err = errMsg ? errMsg : "unknown";
        sqlite3_free(errMsg);
        Logger::instance().error("SQL error: " + err);
        return false;
    }
    return true;
}

// ── Incident History ───────────────────────────────────────────────────────

bool MemoryStore::recordIncident(const IncidentRecord& rec) {
    std::lock_guard lock(mutex_);
    if (!db_) return false;

    const char* sql = "INSERT INTO incidents "
        "(problem, root_cause, action_taken, result, severity, "
        "health_before, health_after, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    std::string ts = rec.timestamp.empty() ? nowTimestamp() : rec.timestamp;
    sqlite3_bind_text(stmt, 1, rec.problem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec.rootCause.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec.actionTaken.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, rec.result.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, rec.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 6, rec.healthBefore);
    sqlite3_bind_double(stmt, 7, rec.healthAfter);
    sqlite3_bind_text(stmt, 8, ts.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

std::vector<IncidentRecord> MemoryStore::getRecentIncidents(int limit) const {
    std::lock_guard lock(mutex_);
    std::vector<IncidentRecord> results;
    if (!db_) return results;

    const char* sql = "SELECT id, problem, root_cause, action_taken, result, "
        "severity, health_before, health_after, timestamp "
        "FROM incidents ORDER BY id DESC LIMIT ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        IncidentRecord r;
        r.id = sqlite3_column_int64(stmt, 0);
        r.problem     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.rootCause   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2) ?: reinterpret_cast<const unsigned char*>(""));
        r.actionTaken = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3) ?: reinterpret_cast<const unsigned char*>(""));
        r.result      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4) ?: reinterpret_cast<const unsigned char*>(""));
        r.severity    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5) ?: reinterpret_cast<const unsigned char*>(""));
        r.healthBefore = sqlite3_column_double(stmt, 6);
        r.healthAfter  = sqlite3_column_double(stmt, 7);
        r.timestamp   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<IncidentRecord> MemoryStore::getIncidentsByProblem(
    const std::string& problem, int limit) const
{
    std::lock_guard lock(mutex_);
    std::vector<IncidentRecord> results;
    if (!db_) return results;

    const char* sql = "SELECT id, problem, root_cause, action_taken, result, "
        "severity, health_before, health_after, timestamp "
        "FROM incidents WHERE problem LIKE ? ORDER BY id DESC LIMIT ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    std::string pattern = "%" + problem + "%";
    sqlite3_bind_text(stmt, 1, pattern.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        IncidentRecord r;
        r.id = sqlite3_column_int64(stmt, 0);
        r.problem = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.rootCause = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2) ?: reinterpret_cast<const unsigned char*>(""));
        r.actionTaken = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3) ?: reinterpret_cast<const unsigned char*>(""));
        r.result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4) ?: reinterpret_cast<const unsigned char*>(""));
        r.severity = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5) ?: reinterpret_cast<const unsigned char*>(""));
        r.healthBefore = sqlite3_column_double(stmt, 6);
        r.healthAfter = sqlite3_column_double(stmt, 7);
        r.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return results;
}

// ── Security Events ────────────────────────────────────────────────────────

bool MemoryStore::recordSecurityEvent(const SecurityEvent& ev) {
    std::lock_guard lock(mutex_);
    if (!db_) return false;

    const char* sql = "INSERT INTO security_events "
        "(type, details, action_taken, outcome, severity, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    std::string ts = ev.timestamp.empty() ? nowTimestamp() : ev.timestamp;
    sqlite3_bind_text(stmt, 1, ev.type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ev.details.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, ev.actionTaken.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, ev.outcome.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, ev.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, ts.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

std::vector<SecurityEvent> MemoryStore::getRecentSecurityEvents(int limit) const {
    std::lock_guard lock(mutex_);
    std::vector<SecurityEvent> results;
    if (!db_) return results;

    const char* sql = "SELECT id, type, details, action_taken, outcome, severity, timestamp "
        "FROM security_events ORDER BY id DESC LIMIT ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;
    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        SecurityEvent e;
        e.id = sqlite3_column_int64(stmt, 0);
        e.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        e.details = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2) ?: reinterpret_cast<const unsigned char*>(""));
        e.actionTaken = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3) ?: reinterpret_cast<const unsigned char*>(""));
        e.outcome = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4) ?: reinterpret_cast<const unsigned char*>(""));
        e.severity = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5) ?: reinterpret_cast<const unsigned char*>(""));
        e.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        results.push_back(std::move(e));
    }
    sqlite3_finalize(stmt);
    return results;
}

// ── Action Statistics ──────────────────────────────────────────────────────

bool MemoryStore::updateActionStats(const std::string& actionName, bool success) {
    std::lock_guard lock(mutex_);
    if (!db_) return false;

    std::string ts = nowTimestamp();
    const char* sql =
        "INSERT INTO action_stats (action_name, total_attempts, successes, failures, last_used) "
        "VALUES (?, 1, ?, ?, ?) "
        "ON CONFLICT(action_name) DO UPDATE SET "
        "total_attempts = total_attempts + 1, "
        "successes = successes + ?, "
        "failures = failures + ?, "
        "last_used = ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    int s = success ? 1 : 0;
    int f = success ? 0 : 1;
    sqlite3_bind_text(stmt, 1, actionName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, s);
    sqlite3_bind_int(stmt, 3, f);
    sqlite3_bind_text(stmt, 4, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, s);
    sqlite3_bind_int(stmt, 6, f);
    sqlite3_bind_text(stmt, 7, ts.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

std::optional<ActionStats> MemoryStore::getActionStats(
    const std::string& actionName) const
{
    std::lock_guard lock(mutex_);
    if (!db_) return std::nullopt;

    const char* sql = "SELECT action_name, total_attempts, successes, failures, last_used "
        "FROM action_stats WHERE action_name = ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, actionName.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        ActionStats as;
        as.actionName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        as.totalAttempts = sqlite3_column_int64(stmt, 1);
        as.successes = sqlite3_column_int64(stmt, 2);
        as.failures = sqlite3_column_int64(stmt, 3);
        as.lastUsed = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4) ?: reinterpret_cast<const unsigned char*>(""));
        as.successRate = (as.totalAttempts > 0)
            ? static_cast<double>(as.successes) / static_cast<double>(as.totalAttempts)
            : 0.0;
        sqlite3_finalize(stmt);
        return as;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<ActionStats> MemoryStore::getAllActionStats() const {
    std::lock_guard lock(mutex_);
    std::vector<ActionStats> results;
    if (!db_) return results;

    const char* sql = "SELECT action_name, total_attempts, successes, failures, last_used "
        "FROM action_stats ORDER BY "
        "CAST(successes AS REAL) / MAX(total_attempts, 1) DESC;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ActionStats as;
        as.actionName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        as.totalAttempts = sqlite3_column_int64(stmt, 1);
        as.successes = sqlite3_column_int64(stmt, 2);
        as.failures = sqlite3_column_int64(stmt, 3);
        as.lastUsed = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4) ?: reinterpret_cast<const unsigned char*>(""));
        as.successRate = (as.totalAttempts > 0)
            ? static_cast<double>(as.successes) / static_cast<double>(as.totalAttempts)
            : 0.0;
        results.push_back(std::move(as));
    }
    sqlite3_finalize(stmt);
    return results;
}

double MemoryStore::getActionSuccessRate(const std::string& actionName) const {
    auto stats = getActionStats(actionName);
    return stats ? stats->successRate : -1.0;
}

// ── User Preferences ───────────────────────────────────────────────────────

bool MemoryStore::setUserPreference(const std::string& key,
                                     const std::string& value, bool enabled)
{
    std::lock_guard lock(mutex_);
    if (!db_) return false;

    const char* sql = "INSERT OR REPLACE INTO user_preferences (key, value, enabled) "
        "VALUES (?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, enabled ? 1 : 0);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

std::optional<UserPreference> MemoryStore::getUserPreference(
    const std::string& key) const
{
    std::lock_guard lock(mutex_);
    if (!db_) return std::nullopt;

    const char* sql = "SELECT key, value, enabled FROM user_preferences WHERE key = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        UserPreference p;
        p.key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        p.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1) ?: reinterpret_cast<const unsigned char*>(""));
        p.enabled = sqlite3_column_int(stmt, 2) != 0;
        sqlite3_finalize(stmt);
        return p;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<UserPreference> MemoryStore::getAllUserPreferences() const {
    std::lock_guard lock(mutex_);
    std::vector<UserPreference> results;
    if (!db_) return results;

    const char* sql = "SELECT key, value, enabled FROM user_preferences;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        UserPreference p;
        p.key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        p.value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1) ?: reinterpret_cast<const unsigned char*>(""));
        p.enabled = sqlite3_column_int(stmt, 2) != 0;
        results.push_back(std::move(p));
    }
    sqlite3_finalize(stmt);
    return results;
}

bool MemoryStore::removeUserPreference(const std::string& key) {
    std::lock_guard lock(mutex_);
    if (!db_) return false;
    return execSql("DELETE FROM user_preferences WHERE key = '" + key + "';");
}

// ── AI Planner Formatted Output ────────────────────────────────────────────

std::string MemoryStore::actionStatsForPlanner() const {
    auto stats = getAllActionStats();
    if (stats.empty()) return "No historical action data yet.\n";

    std::ostringstream oss;
    oss << "ACTION SUCCESS RATES:\n";
    for (const auto& s : stats) {
        oss << "  " << s.actionName
            << " — Success Rate: " << static_cast<int>(s.successRate * 100) << "%"
            << " (" << s.successes << "/" << s.totalAttempts << ")\n";
    }
    return oss.str();
}

std::string MemoryStore::incidentHistoryForPlanner(int limit) const {
    auto incidents = getRecentIncidents(limit);
    if (incidents.empty()) return "No incident history yet.\n";

    std::ostringstream oss;
    oss << "RECENT INCIDENTS:\n";
    for (const auto& i : incidents) {
        oss << "  [" << i.severity << "] " << i.problem
            << " → Action: " << i.actionTaken
            << " → Result: " << i.result
            << " (health " << i.healthBefore << " → " << i.healthAfter << ")\n";
    }
    return oss.str();
}

std::string MemoryStore::preferencesForPlanner() const {
    auto prefs = getAllUserPreferences();
    if (prefs.empty()) return "No user preferences configured.\n";

    std::ostringstream oss;
    oss << "USER PREFERENCES:\n";
    for (const auto& p : prefs) {
        oss << "  " << p.key << ": " << p.value
            << (p.enabled ? " (active)" : " (disabled)") << "\n";
    }
    return oss.str();
}

} // namespace fikcer::agent

// ============================================================================
// FikcerAgent – Dear ImGui Desktop GUI Implementation
// ============================================================================
#define GL_SILENCE_DEPRECATION   // Suppress macOS OpenGL deprecation warnings

#include "gui/app.h"
#include "gui/native_save_dialog.h"
#include "config.h"
#include "utils/logger.h"
#include "utils/notify.h"

#include "vendor/imgui/imgui.h"
#include "vendor/imgui/backends/imgui_impl_glfw.h"
#include "vendor/imgui/backends/imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <sstream>
#include <thread>

// ── Colour palette ─────────────────────────────────────────────────────────
namespace col {
    static const ImVec4 Green   {0.30f, 0.85f, 0.40f, 1.0f};
    static const ImVec4 Yellow  {0.95f, 0.80f, 0.25f, 1.0f};
    static const ImVec4 Orange  {0.95f, 0.55f, 0.20f, 1.0f};
    static const ImVec4 Red     {0.95f, 0.30f, 0.25f, 1.0f};
    static const ImVec4 Magenta {0.85f, 0.30f, 0.85f, 1.0f};
    static const ImVec4 Cyan    {0.30f, 0.80f, 0.95f, 1.0f};
    static const ImVec4 White   {1.0f,  1.0f,  1.0f,  1.0f};
    static const ImVec4 Dim     {0.60f, 0.60f, 0.60f, 1.0f};
}

// ── Byte formatter ─────────────────────────────────────────────────────────
static std::string fmtBytes(uint64_t bytes) {
    constexpr double GB = 1024.0 * 1024.0 * 1024.0;
    constexpr double MB = 1024.0 * 1024.0;
    char buf[64];
    if (bytes >= static_cast<uint64_t>(GB))
        std::snprintf(buf, sizeof(buf), "%.1f GB", static_cast<double>(bytes) / GB);
    else
        std::snprintf(buf, sizeof(buf), "%.0f MB", static_cast<double>(bytes) / MB);
    return buf;
}

// ── Friendly anomaly text (mirrors CLI version) ────────────────────────────
static std::string friendlyAnomaly(const fikcer::ai::Anomaly& a) {
    using fikcer::ai::AnomalyType;
    switch (a.type) {
        case AnomalyType::CPU_SPIKE:
            return "Processor is working very hard (" +
                   std::to_string(static_cast<int>(a.metricValue)) + "% used).";
        case AnomalyType::CPU_RAMP:
            return "Processor usage is climbing quickly.";
        case AnomalyType::MEMORY_SPIKE:
            return "Running low on memory (" +
                   std::to_string(static_cast<int>(a.metricValue)) + "% used).";
        case AnomalyType::MEMORY_LEAK:
            return "Memory keeps growing — an app may have a leak.";
        case AnomalyType::PROCESS_CPU_HOG:
            if (!a.relatedProcess.empty())
                return "\"" + a.relatedProcess + "\" is using a lot of processor (" +
                       std::to_string(static_cast<int>(a.metricValue)) + "%).";
            return "A program is hogging the processor.";
        case AnomalyType::PROCESS_MEM_HOG:
            if (!a.relatedProcess.empty())
                return "\"" + a.relatedProcess + "\" is using too much memory.";
            return "A program is using excessive memory.";
        case AnomalyType::SYSTEM_OVERLOAD:
            return "Computer is severely overloaded!";
        case AnomalyType::SLOW_PC:
            return "Computer is likely feeling slow due to sustained load.";
        default:
            return a.description;
    }
}

static ImVec4 severityColor(fikcer::ai::Severity s) {
    using S = fikcer::ai::Severity;
    switch (s) {
        case S::LOW:      return col::Dim;
        case S::MEDIUM:   return col::Yellow;
        case S::HIGH:     return col::Red;
        case S::CRITICAL: return col::Magenta;
    }
    return col::White;
}

static const char* logLevelLabel(fikcer::gui::LogEntry::Level level) {
    switch (level) {
        case fikcer::gui::LogEntry::INFO: return "INFO";
        case fikcer::gui::LogEntry::WARN: return "WARN";
        case fikcer::gui::LogEntry::ERR:  return "ERROR";
    }
    return "INFO";
}

static constexpr std::array<const char*, 5> issueCategories = {
    "Performance",
    "Slow PC",
    "Security",
    "Bug",
    "Other"
};

static std::string timestampSlug() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d-%H%M%S");
    return oss.str();
}

// ── GLFW error callback ───────────────────────────────────────────────────
static void glfwErrorCb(int /*error*/, const char* desc) {
    std::fprintf(stderr, "[GLFW Error] %s\n", desc);
}

// ============================================================================
// App implementation
// ============================================================================

namespace fikcer::gui {

App::App() = default;
App::~App() {
    if (window_) {
        shutdownImGui();
        glfwDestroyWindow(window_);
        glfwTerminate();
    }
}

// ── Initialisation ─────────────────────────────────────────────────────────
bool App::init() {
    // Logger
    auto& logger = utils::Logger::instance();
    if (!logger.init(std::string(config::LOG_DIRECTORY),
                     config::LOG_FILE_PREFIX,
                     config::MAX_LOG_FILE_SIZE,
                     config::MAX_LOG_FILES,
                     utils::LogLevel::INFO)) {
        pushLog(LogEntry::ERR, "Could not start logging system");
        return false;
    }
    logger.info("FikcerAgent v2.0 GUI starting");
    pushLog(LogEntry::INFO, "FikcerAgent v2.0 starting...");

    // Window
    if (!initWindow()) return false;
    initImGui();

    // Setup Agent callback
    agent_.setEventCallback([this](const agent::AgentEvent& ev) {
        auto lvl = LogEntry::INFO;
        if (ev.severity == "warn") lvl = LogEntry::WARN;
        else if (ev.severity == "error" || ev.severity == "critical") lvl = LogEntry::ERR;
        
        // Push to standard log
        pushLog(lvl, ev.message);
        
        // If it's a critical alert or approval, we can also store it in alerts_ queue
        if (ev.type == agent::AgentEvent::ALERT || ev.type == agent::AgentEvent::APPROVAL_NEEDED) {
            std::lock_guard lock(mutex_);
            ai::Anomaly a;
            a.description = ev.message;
            if (ev.severity == "critical") a.severity = ai::Severity::CRITICAL;
            else if (ev.severity == "error") a.severity = ai::Severity::HIGH;
            else a.severity = ai::Severity::MEDIUM;
            
            alerts_.push_front(a);
            if (alerts_.size() > MAX_ALERTS) alerts_.pop_back();
        }
    });

    if (!agent_.init()) {
        pushLog(LogEntry::ERR, "Failed to initialise Agent orchestrator");
        return false;
    }
    
    if (!agent_.start()) {
        pushLog(LogEntry::ERR, "Failed to start Agent loop");
        return false;
    }

    pushLog(LogEntry::INFO, "All modules ready. Protecting your computer!");
    return true;
}

// ── Window creation ────────────────────────────────────────────────────────
bool App::initWindow() {
    glfwSetErrorCallback(glfwErrorCb);
    if (!glfwInit()) {
        std::fprintf(stderr, "GLFW init failed\n");
        return false;
    }

    // OpenGL 3.2 core (macOS requirement)
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    window_ = glfwCreateWindow(1100, 750, "FikcerAgent – AI System Guardian", nullptr, nullptr);
    if (!window_) {
        glfwTerminate();
        return false;
    }
    glfwMakeContextCurrent(window_);
    glfwSwapInterval(1);  // vsync
    return true;
}

// ── ImGui setup ────────────────────────────────────────────────────────────
void App::initImGui() {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Dark theme with custom tweaks
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding   = 6.0f;
    style.FrameRounding    = 4.0f;
    style.GrabRounding     = 4.0f;
    style.TabRounding      = 4.0f;
    style.ScrollbarRounding= 6.0f;
    style.WindowPadding    = ImVec2(12, 12);
    style.FramePadding     = ImVec2(8, 4);
    style.ItemSpacing      = ImVec2(8, 6);

    // Colour overrides for a sleek dark look
    auto* colors = style.Colors;
    colors[ImGuiCol_WindowBg]       = ImVec4(0.09f, 0.09f, 0.11f, 1.00f);
    colors[ImGuiCol_TitleBg]        = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
    colors[ImGuiCol_TitleBgActive]  = ImVec4(0.12f, 0.12f, 0.16f, 1.00f);
    colors[ImGuiCol_Tab]            = ImVec4(0.12f, 0.12f, 0.16f, 1.00f);
    colors[ImGuiCol_TabSelected]    = ImVec4(0.22f, 0.28f, 0.45f, 1.00f);
    colors[ImGuiCol_TabHovered]     = ImVec4(0.28f, 0.34f, 0.55f, 1.00f);
    colors[ImGuiCol_FrameBg]        = ImVec4(0.14f, 0.14f, 0.18f, 1.00f);
    colors[ImGuiCol_Button]         = ImVec4(0.20f, 0.25f, 0.40f, 1.00f);
    colors[ImGuiCol_ButtonHovered]  = ImVec4(0.28f, 0.34f, 0.55f, 1.00f);
    colors[ImGuiCol_ButtonActive]   = ImVec4(0.35f, 0.42f, 0.65f, 1.00f);
    colors[ImGuiCol_Header]         = ImVec4(0.18f, 0.22f, 0.35f, 1.00f);
    colors[ImGuiCol_HeaderHovered]  = ImVec4(0.25f, 0.30f, 0.48f, 1.00f);
    colors[ImGuiCol_HeaderActive]   = ImVec4(0.30f, 0.36f, 0.55f, 1.00f);

    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init("#version 150");
}

void App::shutdownImGui() {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
}

void App::newFrame() {
    glfwPollEvents();
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
}

void App::render() {
    ImGui::Render();
    int fbW, fbH;
    glfwGetFramebufferSize(window_, &fbW, &fbH);
    glViewport(0, 0, fbW, fbH);
    glClearColor(0.07f, 0.07f, 0.09f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(window_);
}

// ── Main loop ──────────────────────────────────────────────────────────────
void App::run() {
    while (!glfwWindowShouldClose(window_) && !shutdownRequested_) {
        newFrame();

        // ── Full-window ImGui layout ───────────────────────────────────────
        {
            const ImGuiViewport* vp = ImGui::GetMainViewport();
            ImGui::SetNextWindowPos(vp->WorkPos);
            ImGui::SetNextWindowSize(vp->WorkSize);

            ImGuiWindowFlags wf = ImGuiWindowFlags_NoTitleBar |
                                  ImGuiWindowFlags_NoResize |
                                  ImGuiWindowFlags_NoMove |
                                  ImGuiWindowFlags_NoCollapse |
                                  ImGuiWindowFlags_NoBringToFrontOnFocus;

            ImGui::Begin("##Main", nullptr, wf);

            // Title bar
            ImGui::PushStyleColor(ImGuiCol_Text, col::Cyan);
            ImGui::SetWindowFontScale(1.3f);
            ImGui::Text("FikcerAgent");
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::TextColored(col::Dim, "AI-Powered System Guardian");
            ImGui::SameLine(ImGui::GetWindowWidth() - 200);

            // Overall health indicator
            float healthScore = static_cast<float>(agent_.healthScore());
            if (healthScore >= 90.0f)
                ImGui::TextColored(col::Green,   "Status: Healthy (%.1f)", healthScore);
            else if (healthScore >= 75.0f)
                ImGui::TextColored(col::Yellow,  "Status: Moderate (%.1f)", healthScore);
            else if (healthScore >= 50.0f)
                ImGui::TextColored(col::Orange,  "Status: Elevated (%.1f)", healthScore);
            else
                ImGui::TextColored(col::Red,     "Status: Critical! (%.1f)", healthScore);

            ImGui::Separator();

            // Tabs
            if (ImGui::BeginTabBar("##Tabs", ImGuiTabBarFlags_None)) {
                if (ImGui::BeginTabItem("Dashboard")) {
                    drawDashboard();
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Alerts")) {
                    drawAlerts();
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("AI")) {
                    drawGeminiPanel();
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Security")) {
                    drawSecurityPanel();
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Reports")) {
                    drawIssueReporter();
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Log")) {
                    drawLogViewer();
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }

            ImGui::End();
        }

        render();
    }

    // Shutdown
    pushLog(LogEntry::INFO, "FikcerAgent shutting down...");
    agent_.stop();
    utils::Logger::instance().shutdown();
}

void App::requestShutdown() {
    shutdownRequested_ = true;
}

// ============================================================================
// Dashboard tab
// ============================================================================
void App::drawDashboard() {
    auto ws = agent_.worldState();
    
    float cpu = static_cast<float>(ws.cpuPercent);
    float mem = static_cast<float>(ws.memPercent);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Update history graphs
        cpuHistory_.push_back(cpu);
        if (cpuHistory_.size() > MAX_GRAPH_SAMPLES) cpuHistory_.pop_front();
        
        memHistory_.push_back(mem);
        if (memHistory_.size() > MAX_GRAPH_SAMPLES) memHistory_.pop_front();
    }

    ImGui::Spacing();

    // ── Live Activity Feed ─────────────────────────────────────────────────
    ImGui::TextColored(col::Cyan, "What the AI is Doing Now:");
    ImGui::Separator();
    drawActivityFeed();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ── CPU gauge ──────────────────────────────────────────────────────────
    drawHealthGauge("Processor (CPU)", cpu / 100.0f, 0.50f, 0.90f);
    ImGui::SameLine();
    char cpuLabel[64];
    std::snprintf(cpuLabel, sizeof(cpuLabel), "%.1f%%", cpu);
    ImGui::Text("%s", cpuLabel);

    // ── Memory gauge ───────────────────────────────────────────────────────
    drawHealthGauge("Memory (RAM)", mem / 100.0f, 0.50f, 0.90f);
    ImGui::SameLine();
    char memLabel[128];
    std::snprintf(memLabel, sizeof(memLabel), "%.1f%%", mem);
    ImGui::Text("%s", memLabel);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ── History graphs ─────────────────────────────────────────────────────
    ImGui::Text("CPU History");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!cpuHistory_.empty()) {
            std::vector<float> cpuVec(cpuHistory_.begin(), cpuHistory_.end());
            ImGui::PlotLines("##cpuGraph", cpuVec.data(),
                             static_cast<int>(cpuVec.size()),
                             0, nullptr, 0.0f, 100.0f, ImVec2(-1, 80));
        } else {
            ImGui::TextColored(col::Dim, "Collecting data...");
        }
    }

    ImGui::Spacing();
    ImGui::Text("Memory History");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!memHistory_.empty()) {
            std::vector<float> memVec(memHistory_.begin(), memHistory_.end());
            ImGui::PlotLines("##memGraph", memVec.data(),
                             static_cast<int>(memVec.size()),
                             0, nullptr, 0.0f, 100.0f, ImVec2(-1, 80));
        } else {
            ImGui::TextColored(col::Dim, "Collecting data...");
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ── Quick stats ────────────────────────────────────────────────────────
    ImGui::Columns(3, "##statsCol", false);
    
    // Show Goals
    auto goals = agent_.goals();
    int metGoals = 0;
    for (const auto& g : goals) {
        if (g.satisfied) metGoals++;
    }
    
    ImGui::TextColored(col::Cyan, "Goals Met");
    ImGui::Text("%d / %d", metGoals, static_cast<int>(goals.size()));
    
    ImGui::NextColumn();
    
    ImGui::TextColored(col::Cyan, "Pending Approvals");
    ImGui::Text("%d", static_cast<int>(agent_.pendingApprovals().size()));
    
    ImGui::NextColumn();
    
    ImGui::TextColored(col::Cyan, "Total Actions");
    ImGui::Text("%llu", static_cast<unsigned long long>(agent_.memory().getAllActionStats().size()));
    
    ImGui::Columns(1);
}

// ============================================================================
// Alerts tab
// ============================================================================
void App::drawAlerts() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (alerts_.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(col::Green, "  No active alerts. Your computer is running smoothly!");
        return;
    }

    ImGui::Spacing();
    ImGui::TextColored(col::Dim, "Showing %zu most recent alert(s):",
                       alerts_.size());
    ImGui::Spacing();

    if (ImGui::Button("Clear All")) {
        alerts_.clear();
        return;
    }
    ImGui::Separator();

    for (int i = static_cast<int>(alerts_.size()) - 1; i >= 0; --i) {
        const auto& a = alerts_[static_cast<size_t>(i)];
        ImGui::PushID(i);

        ImVec4 c = severityColor(a.severity);
        const char* sevLabel = "INFO";
        switch (a.severity) {
            case ai::Severity::LOW:      sevLabel = "LOW";      break;
            case ai::Severity::MEDIUM:   sevLabel = "MEDIUM";   break;
            case ai::Severity::HIGH:     sevLabel = "HIGH";     break;
            case ai::Severity::CRITICAL: sevLabel = "CRITICAL"; break;
        }

        ImGui::TextColored(c, "[%s]", sevLabel);
        ImGui::SameLine();
        ImGui::TextWrapped("%s", friendlyAnomaly(a).c_str());

        ImGui::PopID();
    }
}

// ============================================================================
// Activity Feed - plain English narrative
// ============================================================================
void App::drawActivityFeed() {
    std::lock_guard<std::mutex> lock(mutex_);

    ImGui::Spacing();
    ImGui::TextColored(col::Cyan, "Live Activity:");
    ImGui::Separator();

    if (logLines_.empty()) {
        ImGui::TextColored(col::Dim, "  (Waiting for the agent to report activity...)");
        return;
    }

    ImGui::BeginChild("##activityScroll", ImVec2(0, 200), ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar);

    // Show the last 15 log lines as a narrative
    const std::size_t start = logLines_.size() > 15 ? logLines_.size() - 15 : 0;
    for (std::size_t i = start; i < logLines_.size(); ++i) {
        const auto& entry = logLines_[i];
        ImVec4 c;
        const char* prefix;
        switch (entry.level) {
            case LogEntry::INFO: c = col::Green;  prefix = "✓"; break;
            case LogEntry::WARN: c = col::Yellow; prefix = "⚠"; break;
            case LogEntry::ERR:  c = col::Red;    prefix = "✕"; break;
            default:             c = col::White;  prefix = "•"; break;
        }
        ImGui::TextColored(c, "%s %s", prefix, entry.text.c_str());
    }

    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20.0f)
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

// ============================================================================
// Gemini AI panel
// ============================================================================
void App::drawGeminiPanel() {
    ImGui::Spacing();

    if (!agent_.geminiReady()) {
        ImGui::TextColored(col::Yellow,
            "Gemini AI is not available. Set the FIKCER_GEMINI_API_KEY "
            "environment variable to enable.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    auto approvals = agent_.pendingApprovals();

    // Status line
    ImGui::TextColored(col::Cyan, "Agent Autonomous Status:");
    ImGui::SameLine();
    ImGui::TextColored(col::Green, "Active");

    ImGui::Separator();
    ImGui::Spacing();

    // Show available skills and tools
    ImGui::TextColored(col::Cyan, "Available Skills & Tools:");
    ImGui::TextColored(col::Dim, 
        "  • Monitoring: CPU, memory, disk, network, firewall, process list\n"
        "  • Recovery: process restart, DNS flush, firewall, cleanup, network reset\n"
        "  • Security: file quarantine, IP blocking, process analysis, startup disable\n"
        "  • Verification: health score, metric checks");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (approvals.empty()) {
        ImGui::TextColored(col::Green, "  No pending approvals. AI has not suggested any restricted actions.");
        
        // Show recent plans briefly
        auto recent = agent_.recentPlans();
        if (!recent.empty()) {
            ImGui::Spacing();
            ImGui::TextColored(col::Dim, "Recent AI Plans:");
            for (const auto& plan : recent) {
                ImGui::BulletText("%s (Score: %.2f)", plan.recommendedAction.c_str(), plan.confidence);
            }
        }
        return;
    }

    // Track which button was pressed
    int applyIdx = -1;
    int skipIdx  = -1;

    // Show each problem with approve/deny buttons
    for (size_t i = 0; i < approvals.size(); ++i) {
        auto& req = approvals[i];
        ImGui::PushID(req.id);

        ImVec4 c = col::Yellow;
        if (req.impact.risk == agent::RiskLevel::HIGH) c = col::Red;

        ImGui::TextColored(c, "[%s RISK]", req.impact.impactDescription.c_str());
        ImGui::SameLine();
        ImGui::TextColored(col::White, "Action: %s", req.plan.recommendedAction.c_str());
        ImGui::TextWrapped("  Issue: %s", req.plan.issue.c_str());
        ImGui::TextWrapped("  Reasoning: %s", req.plan.reasoning.c_str());

        if (!req.approved && !req.denied) {
            if (ImGui::Button("Approve")) {
                applyIdx = req.id;
            }
            ImGui::SameLine();
            if (ImGui::Button("Deny")) {
                skipIdx = req.id;
            }
        } else if (req.approved) {
            if (req.executed) {
                if (req.succeeded)
                    ImGui::TextColored(col::Green, "  Applied successfully: %s", req.resultDetails.c_str());
                else
                    ImGui::TextColored(col::Red, "  Execution failed: %s", req.resultDetails.c_str());
            } else {
                ImGui::TextColored(col::Yellow, "  Pending execution...");
            }
        } else if (req.denied) {
            ImGui::TextColored(col::Dim, "  Denied by user.");
        }

        ImGui::Separator();
        ImGui::PopID();
    }

    if (applyIdx >= 0) {
        agent_.approveAction(applyIdx);
        pushLog(LogEntry::INFO, "Action approved by user.");
    }
    if (skipIdx >= 0) {
        agent_.denyAction(skipIdx);
        pushLog(LogEntry::INFO, "Action denied by user.");
    }
}

// ============================================================================
// Security panel
// ============================================================================
void App::drawSecurityPanel() {
    auto ws = agent_.worldState();

    ImGui::Spacing();

    // Firewall
    ImGui::TextColored(col::Cyan, "Firewall:");
    ImGui::SameLine();
    if (ws.firewallEnabled)
        ImGui::TextColored(col::Green, "Enabled");
    else
        ImGui::TextColored(col::Red, "Disabled — consider turning it on!");

    ImGui::TextColored(col::Cyan, "Network Interface:");
    ImGui::SameLine();
    ImGui::TextColored(col::White, "%s", ws.activeInterface.c_str());

    ImGui::TextColored(col::Cyan, "Gateway:");
    ImGui::SameLine();
    ImGui::TextColored(col::White, "%s", ws.gateway.c_str());

    ImGui::TextColored(col::Cyan, "Internet:");
    ImGui::SameLine();
    if (ws.internetReachable)
        ImGui::TextColored(col::Green, "Connected (ping: %.0f ms)", ws.pingLatencyMs);
    else
        ImGui::TextColored(col::Red, "Offline");

    ImGui::TextColored(col::Cyan, "DNS:");
    ImGui::SameLine();
    if (ws.dnsWorking)
        ImGui::TextColored(col::Green, "Working (%.0f ms)", ws.dnsLatencyMs);
    else
        ImGui::TextColored(col::Red, "Not working");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Suspicious processes
    ImGui::TextColored(col::Cyan, "Active Threats:");
    if (ws.activeThreats.empty()) {
        ImGui::TextColored(col::Green, "  None detected. You're safe!");
    } else {
        for (const auto& sp : ws.activeThreats) {
            ImGui::TextColored(col::Red, "  [!] \"%s\" (PID %u)", sp.name.c_str(), sp.pid);
            ImGui::TextColored(col::Dim, "      Reason: %s", sp.reason.c_str());
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Disk info
    if (!ws.disks.empty()) {
        ImGui::TextColored(col::Cyan, "Disk Usage:");
        for (const auto& d : ws.disks) {
            ImVec4 c = d.usagePercent > 90 ? col::Red :
                       d.usagePercent > 75 ? col::Yellow : col::Green;
            ImGui::TextColored(c, "  %s  %.1f%% used (%s free)",
                               d.mountPoint.c_str(), d.usagePercent,
                               fmtBytes(d.freeBytes).c_str());
        }
    }

    // Battery
    if (ws.hasBattery) {
        ImGui::Spacing();
        ImGui::TextColored(col::Cyan, "Battery:");
        ImVec4 bc = ws.batteryPercent > 20 ? col::Green : col::Red;
        ImGui::TextColored(bc, "  %.0f%% %s",
                           ws.batteryPercent,
                           ws.batteryCharging ? "(charging)" : "");
    }
}

// ============================================================================
// Reports tab
// ============================================================================
void App::drawIssueReporter() {
    ImGui::Spacing();
    ImGui::TextColored(col::Cyan, "Report an issue for FikcerAgent");
    ImGui::TextColored(col::Dim,
        "Send a problem description to the agent so it can investigate it on the next scan.");
    ImGui::Separator();

    ImGui::Text("Category");
    ImGui::SetNextItemWidth(260.0f);
    ImGui::Combo("##issueCategory", &issueCategoryIndex_, issueCategories.data(),
                 static_cast<int>(issueCategories.size()));

    ImGui::Spacing();
    ImGui::Text("Title");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##issueTitle", issueTitle_.data(), issueTitle_.size());

    ImGui::Spacing();
    ImGui::Text("Details");
    ImGui::InputTextMultiline("##issueDetails", issueDetails_.data(),
                              issueDetails_.size(), ImVec2(-1.0f, 160.0f));

    ImGui::Spacing();
    if (ImGui::Button("Send to Agent")) {
        const char* category = issueCategories[issueCategoryIndex_];
        bool accepted = agent_.submitUserIssue(
            category,
            issueTitle_.data(),
            issueDetails_.data());

        if (accepted) {
            pushLog(LogEntry::INFO, std::string("User issue submitted: ") + issueTitle_.data());
            issueTitle_.fill('\0');
            issueDetails_.fill('\0');
            issueCategoryIndex_ = 0;
        } else {
            pushLog(LogEntry::ERR, "Failed to submit user issue report.");
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Export Issue as TXT")) {
        if (exportIssueReport()) {
            pushLog(LogEntry::INFO, "Exported issue report as plain text.");
        } else {
            pushLog(LogEntry::ERR, "Failed to export issue report.");
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextColored(col::Cyan, "Recent reports stored by the agent");
    auto incidents = agent_.memory().getRecentIncidents(5);
    if (incidents.empty()) {
        ImGui::TextColored(col::Dim, "No reports have been recorded yet.");
    } else {
        for (const auto& incident : incidents) {
            ImGui::BulletText("[%s] %s", incident.severity.c_str(), incident.problem.c_str());
            if (!incident.rootCause.empty()) {
                ImGui::TextColored(col::Dim, "  %s", incident.rootCause.c_str());
            }
        }
    }
}

// ============================================================================
// Log viewer
// ============================================================================
void App::drawLogViewer() {
    std::deque<LogEntry> entries;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        entries = logLines_;
    }

    ImGui::Spacing();
    if (ImGui::Button("Clear Log")) {
        std::lock_guard<std::mutex> lock(mutex_);
        logLines_.clear();
        return;
    }
    ImGui::SameLine();
    if (ImGui::Button("Export Logs as TXT")) {
        if (exportLogLines()) {
            pushLog(LogEntry::INFO, "Exported logs as plain text.");
        } else {
            pushLog(LogEntry::ERR, "Failed to export logs.");
        }
    }
    ImGui::Separator();

    ImGui::BeginChild("##logScroll", ImVec2(0, 0), ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto& entry : entries) {
        ImVec4 c;
        const char* prefix;
        switch (entry.level) {
            case LogEntry::INFO: c = col::Dim;    prefix = "[info]"; break;
            case LogEntry::WARN: c = col::Yellow;  prefix = "[warn]"; break;
            case LogEntry::ERR:  c = col::Red;     prefix = "[err] "; break;
            default:             c = col::White;   prefix = "[???] "; break;
        }
        ImGui::TextColored(c, "%s %s", prefix, entry.text.c_str());
    }
    // Auto-scroll to bottom
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20.0f)
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

// ============================================================================
// Health gauge helper
// ============================================================================
void App::drawHealthGauge(const char* label, float value, float warnAt, float critAt) {
    ImVec4 barColor;
    if (value < warnAt)
        barColor = col::Green;
    else if (value < critAt)
        barColor = col::Yellow;
    else
        barColor = col::Red;

    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, barColor);
    ImGui::ProgressBar(value, ImVec2(300, 22), label);
    ImGui::PopStyleColor();
}

// ============================================================================
// Push log entry (thread-safe)
// ============================================================================
void App::pushLog(LogEntry::Level lvl, const std::string& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    logLines_.push_back({lvl, msg});
    while (logLines_.size() > MAX_LOG_LINES)
        logLines_.pop_front();

    // Also push to the file logger
    auto& logger = utils::Logger::instance();
    switch (lvl) {
        case LogEntry::INFO: logger.info(msg); break;
        case LogEntry::WARN: logger.warn(msg); break;
        case LogEntry::ERR:  logger.error(msg); break;
    }
}

bool App::exportLogLines() {
    std::deque<LogEntry> entries;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        entries = logLines_;
    }

    auto savePath = chooseNativeSavePath(
        "Save FikcerAgent Logs",
        "fikcerAgent-logs-" + timestampSlug() + ".txt",
        "txt");
    if (!savePath) {
        return false;
    }

    std::ostringstream content;
    content << "FikcerAgent Log Export\n";
    content << "Generated: " << timestampSlug() << "\n\n";
    for (const auto& entry : entries) {
        content << "[" << logLevelLabel(entry.level) << "] " << entry.text << '\n';
    }

    return writeTextFile(*savePath, content.str());
}

bool App::exportIssueReport() {
    const char* category = (issueCategoryIndex_ >= 0 &&
                            issueCategoryIndex_ < static_cast<int>(issueCategories.size()))
        ? issueCategories[issueCategoryIndex_]
        : "Other";

    std::string title = issueTitle_.data();
    std::string details = issueDetails_.data();
    if (title.empty() || details.empty()) {
        return false;
    }

    auto state = agent_.worldState();
    auto incidents = agent_.memory().getRecentIncidents(5);

    auto savePath = chooseNativeSavePath(
        "Save FikcerAgent Issue Report",
        "fikcerAgent-issue-" + timestampSlug() + ".txt",
        "txt");
    if (!savePath) {
        return false;
    }

    std::ostringstream content;
    content << "FikcerAgent Issue Report\n";
    content << "Generated: " << timestampSlug() << "\n";
    content << "Category: " << category << "\n";
    content << "Title: " << title << "\n\n";
    content << "Details:\n" << details << "\n\n";
    content << "Current System Snapshot:\n" << state.toSummary() << "\n";
    content << "Recent Agent Logs:\n";
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& entry : logLines_) {
            content << "[" << logLevelLabel(entry.level) << "] " << entry.text << '\n';
        }
    }

    content << "\nRecent Recorded Reports:\n";
    for (const auto& incident : incidents) {
        content << "- [" << incident.severity << "] " << incident.problem << '\n';
        if (!incident.rootCause.empty()) {
            content << "  " << incident.rootCause << '\n';
        }
    }

    return writeTextFile(*savePath, content.str());
}

bool App::writeTextFile(const std::filesystem::path& filePath,
                        const std::string& content) {
    std::ofstream out(filePath);
    if (!out.is_open()) {
        return false;
    }

    out << content;
    return static_cast<bool>(out);
}

std::string App::currentTimestampSlug() const {
    return timestampSlug();
}

// End of App

} // namespace fikcer::gui

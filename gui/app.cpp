// ============================================================================
// FikcerAgent – Dear ImGui Desktop GUI Implementation
// ============================================================================
#define GL_SILENCE_DEPRECATION   // Suppress macOS OpenGL deprecation warnings

#include "gui/app.h"
#include "config.h"
#include "utils/logger.h"

#include "vendor/imgui/imgui.h"
#include "vendor/imgui/backends/imgui_impl_glfw.h"
#include "vendor/imgui/backends/imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
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

static ImVec4 gemColor(const std::string& s) {
    if (s == "CRITICAL") return col::Magenta;
    if (s == "HIGH")     return col::Red;
    if (s == "MEDIUM")   return col::Yellow;
    return col::Dim;
}

static std::string friendlyType(const std::string& t) {
    if (t == "DISK_SPACE")  return "Disk Space";
    if (t == "DISK_HEALTH") return "Disk Health";
    if (t == "NETWORK")     return "Network";
    if (t == "DNS")         return "Internet / DNS";
    if (t == "MALWARE")     return "Security Threat";
    if (t == "MEMORY")      return "Memory";
    if (t == "CPU")         return "Processor";
    if (t == "TEMPERATURE") return "Overheating";
    if (t == "BATTERY")     return "Battery";
    if (t == "DRIVER")      return "Driver Issue";
    if (t == "INTEGRITY")   return "System Files";
    if (t == "STARTUP")     return "Startup Programs";
    return t;
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

    // Monitor
    monitor_.setCallback([this](const core::SystemStats& s) { onStats(s); });
    if (!monitor_.start(config::MONITOR_INTERVAL_MS)) {
        pushLog(LogEntry::ERR, "Could not start health monitor");
        return false;
    }
    pushLog(LogEntry::INFO, "Health monitor started");

    // Process manager
#ifdef _WIN32
    procMgr_.addToWhitelist("notepad.exe");
    procMgr_.addToWhitelist("explorer.exe");
    procMgr_.addToWhitelist("calc.exe");
#elif defined(__APPLE__)
    procMgr_.addToWhitelist("TextEdit");
    procMgr_.addToWhitelist("Calculator");
    procMgr_.addToWhitelist("Notes");
#endif
    procMgr_.setHungCallback([this](const actions::ProcessInfo& info) {
        pushLog(LogEntry::WARN, "\"" + info.name + "\" appears frozen");
    });
    if (!procMgr_.start(config::PROCESS_SCAN_INTERVAL_MS)) {
        pushLog(LogEntry::ERR, "Could not start process manager");
        monitor_.stop();
        return false;
    }
    pushLog(LogEntry::INFO, "Process manager started");

    // Anomaly detector
    detector_.setCallback([this](const std::vector<ai::Anomaly>& a) { onAnomalies(a); });

    healer_.setCallback([this](const actions::HealRecord& rec) {
        auto lvl = rec.success ? LogEntry::INFO : LogEntry::WARN;
        pushLog(lvl, "Heal: " + rec.description +
                     (rec.success ? " (ok)" : " (failed)"));
    });

    // Gemini
    geminiReady_ = gemini_.init();
    if (geminiReady_) {
        pushLog(LogEntry::INFO,
                "Gemini AI connected (model: " + gemini_.modelName() + ")");
    } else {
        pushLog(LogEntry::WARN,
                "Gemini AI not available — using local detection only.");
    }

    // System fixer
    fixer_.setCallback([this](const actions::FixRecord& rec) {
        auto lvl = rec.success ? LogEntry::INFO : LogEntry::WARN;
        pushLog(lvl, "Fix [" + rec.problemType + "]: " + rec.fixApplied +
                     (rec.success ? " (ok)" : " (failed)"));
    });

    pushLog(LogEntry::INFO, "All modules ready. Protecting your computer!");

    // Timing – schedule first deep scan after 10 s
    lastHeuristic_ = std::chrono::steady_clock::now();
    lastDeep_ = std::chrono::steady_clock::now()
                - std::chrono::milliseconds(config::DEEP_SCAN_INTERVAL_MS - 10000);

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

        // ── Background tick: heuristic ─────────────────────────────────────
        auto now = std::chrono::steady_clock::now();
        auto hElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - lastHeuristic_).count();
        if (hElapsed >= config::AI_SCAN_INTERVAL_MS) {
            lastHeuristic_ = now;
            auto procs  = ai::AnomalyDetector::sampleProcessResources();
            auto latest = monitor_.latestStats();
            detector_.feed(latest, procs);
        }

        // ── Background tick: deep scan + Gemini ────────────────────────────
        if (geminiReady_ && !deepScanRunning_) {
            auto dElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - lastDeep_).count();
            if (dElapsed >= config::DEEP_SCAN_INTERVAL_MS) {
                lastDeep_ = now;
                deepScanRunning_ = true;
                deepScanStatus_ = "Scanning...";

                // Run deep scan on a worker thread to avoid freezing UI
                std::thread([this]() {
                    pushLog(LogEntry::INFO, "Running deep system scan...");

                    auto diag   = scanner_.scan();
                    auto latest = monitor_.latestStats();

                    std::string report = core::SystemScanner::generateReport(
                        diag, latest.cpuUsagePercent, latest.memUsagePercent,
                        latest.memTotalBytes, latest.memAvailableBytes);

                    auto problems = gemini_.analyseSystem(report);

                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        lastDiag_ = diag;
                        geminiProblems_ = problems;
                        suspiciousProcs_ = diag.suspiciousProcesses;
                        firewallEnabled_ = diag.firewallEnabled;
                        networkStatus_  = diag.network;

                        // Build pending fixes
                        pendingFixes_.clear();
                        for (const auto& p : problems) {
                            PendingFix pf;
                            pf.problem = p;
                            pendingFixes_.push_back(std::move(pf));
                        }

                        deepScanRunning_ = false;
                        if (problems.empty()) {
                            deepScanStatus_ = "Healthy – no issues found";
                            pushLog(LogEntry::INFO, "Gemini AI: Everything looks healthy!");
                        } else {
                            deepScanStatus_ = std::to_string(problems.size()) +
                                              " issue(s) found";
                            pushLog(LogEntry::WARN, "Gemini found " +
                                    std::to_string(problems.size()) + " issue(s)");
                        }
                    }
                }).detach();
            }
        }

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
            float cpu, mem;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cpu = static_cast<float>(latestStats_.cpuUsagePercent);
                mem = static_cast<float>(latestStats_.memUsagePercent);
            }
            float worst = std::max(cpu, mem);
            if (worst < 50.0f)
                ImGui::TextColored(col::Green,   "Status: Healthy");
            else if (worst < 75.0f)
                ImGui::TextColored(col::Yellow,  "Status: Moderate");
            else if (worst < 90.0f)
                ImGui::TextColored(col::Orange,  "Status: Elevated");
            else
                ImGui::TextColored(col::Red,     "Status: Critical!");

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
    procMgr_.stop();
    monitor_.stop();
    utils::Logger::instance().shutdown();
}

void App::requestShutdown() {
    shutdownRequested_ = true;
}

// ============================================================================
// Dashboard tab
// ============================================================================
void App::drawDashboard() {
    std::lock_guard<std::mutex> lock(mutex_);

    float cpu  = static_cast<float>(latestStats_.cpuUsagePercent);
    float mem  = static_cast<float>(latestStats_.memUsagePercent);
    uint64_t memTotal = latestStats_.memTotalBytes;
    uint64_t memAvail = latestStats_.memAvailableBytes;

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
    std::snprintf(memLabel, sizeof(memLabel), "%.1f%%  (%s used of %s)",
                  mem,
                  fmtBytes(memTotal - memAvail).c_str(),
                  fmtBytes(memTotal).c_str());
    ImGui::Text("%s", memLabel);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ── History graphs ─────────────────────────────────────────────────────
    ImGui::Text("CPU History");
    if (!cpuHistory_.empty()) {
        std::vector<float> cpuVec(cpuHistory_.begin(), cpuHistory_.end());
        ImGui::PlotLines("##cpuGraph", cpuVec.data(),
                         static_cast<int>(cpuVec.size()),
                         0, nullptr, 0.0f, 100.0f, ImVec2(-1, 80));
    } else {
        ImGui::TextColored(col::Dim, "Collecting data...");
    }

    ImGui::Spacing();
    ImGui::Text("Memory History");
    if (!memHistory_.empty()) {
        std::vector<float> memVec(memHistory_.begin(), memHistory_.end());
        ImGui::PlotLines("##memGraph", memVec.data(),
                         static_cast<int>(memVec.size()),
                         0, nullptr, 0.0f, 100.0f, ImVec2(-1, 80));
    } else {
        ImGui::TextColored(col::Dim, "Collecting data...");
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ── Quick stats ────────────────────────────────────────────────────────
    ImGui::Columns(3, "##statsCol", false);
    ImGui::TextColored(col::Cyan, "Processes Healed");
    ImGui::Text("%llu terminated, %llu restarted",
                static_cast<unsigned long long>(healer_.totalTerminations()),
                static_cast<unsigned long long>(healer_.totalRestarts()));
    ImGui::NextColumn();
    ImGui::TextColored(col::Cyan, "Memory Cleanups");
    ImGui::Text("%llu",
                static_cast<unsigned long long>(healer_.totalPurgeCaches()));
    ImGui::NextColumn();
    ImGui::TextColored(col::Cyan, "Fixes Applied");
    ImGui::Text("%llu applied, %llu failed",
                static_cast<unsigned long long>(fixer_.totalFixesApplied()),
                static_cast<unsigned long long>(fixer_.totalFixesFailed()));
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
// Gemini AI panel
// ============================================================================
void App::drawGeminiPanel() {
    ImGui::Spacing();

    if (!geminiReady_) {
        ImGui::TextColored(col::Yellow,
            "Gemini AI is not available. Set the FIKCER_GEMINI_API_KEY "
            "environment variable to enable.");
        return;
    }

    // Status line
    ImGui::TextColored(col::Cyan, "Deep Scan Status:");
    ImGui::SameLine();
    if (deepScanRunning_) {
        ImGui::TextColored(col::Yellow, "%s", deepScanStatus_.c_str());
    } else {
        ImGui::Text("%s", deepScanStatus_.c_str());
    }

    ImGui::SameLine(ImGui::GetWindowWidth() - 220);
    if (ImGui::Button("Run Deep Scan Now") && !deepScanRunning_) {
        // Force immediate deep scan
        lastDeep_ = std::chrono::steady_clock::now()
                    - std::chrono::milliseconds(config::DEEP_SCAN_INTERVAL_MS + 1000);
    }

    ImGui::Separator();
    ImGui::Spacing();

    std::lock_guard<std::mutex> lock(mutex_);

    if (pendingFixes_.empty() && !deepScanRunning_) {
        ImGui::TextColored(col::Green,
            "  No issues found by Gemini AI. All clear!");
        return;
    }

    // Show each problem with approve/deny buttons
    for (size_t i = 0; i < pendingFixes_.size(); ++i) {
        auto& pf = pendingFixes_[i];
        ImGui::PushID(static_cast<int>(i));

        ImVec4 c = gemColor(pf.problem.severity);
        ImGui::TextColored(c, "[%s]", pf.problem.severity.c_str());
        ImGui::SameLine();
        ImGui::TextColored(col::White, "%s",
                           friendlyType(pf.problem.type).c_str());
        ImGui::TextWrapped("  %s", pf.problem.description.c_str());

        if (pf.problem.fixType != "NONE" && !pf.problem.fixDescription.empty()) {
            ImGui::TextColored(col::Cyan, "  Suggested fix: %s",
                               pf.problem.fixDescription.c_str());

            if (!pf.applied && !pf.denied) {
                if (ImGui::Button("Apply Fix")) {
                    pf.approved = true;
                    pf.applied = true;

                    // Execute the fix
                    std::vector<ai::GeminiProblem> single = {pf.problem};
                    auto results = fixer_.fixProblems(single);
                    pf.succeeded = !results.empty() && results[0].success;

                    if (pf.succeeded)
                        pushLog(LogEntry::INFO, "Fix applied: " + pf.problem.fixDescription);
                    else
                        pushLog(LogEntry::WARN, "Fix failed: " + pf.problem.fixDescription);
                }
                ImGui::SameLine();
                if (ImGui::Button("Skip")) {
                    pf.denied = true;
                    pushLog(LogEntry::INFO, "Fix skipped: " + pf.problem.fixDescription);
                }
            } else if (pf.applied) {
                if (pf.succeeded)
                    ImGui::TextColored(col::Green, "  Applied successfully!");
                else
                    ImGui::TextColored(col::Red, "  Fix failed — may need admin permissions.");
            } else if (pf.denied) {
                ImGui::TextColored(col::Dim, "  Skipped by user.");
            }
        }

        ImGui::Separator();
        ImGui::PopID();
    }
}

// ============================================================================
// Security panel
// ============================================================================
void App::drawSecurityPanel() {
    std::lock_guard<std::mutex> lock(mutex_);

    ImGui::Spacing();

    // Firewall
    ImGui::TextColored(col::Cyan, "Firewall:");
    ImGui::SameLine();
    if (firewallEnabled_)
        ImGui::TextColored(col::Green, "Enabled");
    else
        ImGui::TextColored(col::Red, "Disabled — consider turning it on!");

    // Network
    ImGui::TextColored(col::Cyan, "Internet:");
    ImGui::SameLine();
    if (networkStatus_.internetReachable)
        ImGui::TextColored(col::Green, "Connected");
    else
        ImGui::TextColored(col::Red, "Not reachable");

    ImGui::TextColored(col::Cyan, "DNS:");
    ImGui::SameLine();
    if (networkStatus_.dnsWorking)
        ImGui::TextColored(col::Green, "Working (%.0f ms)", networkStatus_.dnsLatencyMs);
    else
        ImGui::TextColored(col::Red, "Not working");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Suspicious processes
    ImGui::TextColored(col::Cyan, "Suspicious Processes:");
    if (suspiciousProcs_.empty()) {
        ImGui::TextColored(col::Green, "  None detected. You're safe!");
    } else {
        for (const auto& sp : suspiciousProcs_) {
            ImGui::TextColored(col::Red, "  [!] \"%s\" (PID %u)",
                               sp.name.c_str(), sp.pid);
            ImGui::TextColored(col::Dim, "      Reason: %s", sp.reason.c_str());
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Disk info
    if (!lastDiag_.disks.empty()) {
        ImGui::TextColored(col::Cyan, "Disk Usage:");
        for (const auto& d : lastDiag_.disks) {
            ImVec4 c = d.usagePercent > 90 ? col::Red :
                       d.usagePercent > 75 ? col::Yellow : col::Green;
            ImGui::TextColored(c, "  %s  %.1f%% used (%s free)",
                               d.mountPoint.c_str(), d.usagePercent,
                               fmtBytes(d.freeBytes).c_str());
        }
    }

    // Battery
    if (lastDiag_.battery.hasBattery) {
        ImGui::Spacing();
        ImGui::TextColored(col::Cyan, "Battery:");
        ImVec4 bc = lastDiag_.battery.chargePercent > 20 ? col::Green : col::Red;
        ImGui::TextColored(bc, "  %.0f%% %s  (%s)",
                           lastDiag_.battery.chargePercent,
                           lastDiag_.battery.isCharging ? "(charging)" : "",
                           lastDiag_.battery.condition.c_str());
    }
}

// ============================================================================
// Log viewer
// ============================================================================
void App::drawLogViewer() {
    std::lock_guard<std::mutex> lock(mutex_);

    ImGui::Spacing();
    if (ImGui::Button("Clear Log")) {
        logLines_.clear();
        return;
    }
    ImGui::Separator();

    ImGui::BeginChild("##logScroll", ImVec2(0, 0), ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto& entry : logLines_) {
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

// ============================================================================
// Backend callbacks
// ============================================================================
void App::onStats(const core::SystemStats& stats) {
    std::lock_guard<std::mutex> lock(mutex_);
    latestStats_ = stats;

    cpuHistory_.push_back(static_cast<float>(stats.cpuUsagePercent));
    memHistory_.push_back(static_cast<float>(stats.memUsagePercent));
    while (cpuHistory_.size() > MAX_GRAPH_SAMPLES) cpuHistory_.pop_front();
    while (memHistory_.size() > MAX_GRAPH_SAMPLES) memHistory_.pop_front();
}

void App::onAnomalies(const std::vector<ai::Anomaly>& anomalies) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& a : anomalies) {
        alerts_.push_back(a);
    }
    while (alerts_.size() > MAX_ALERTS) alerts_.pop_front();

    // Let healer act (outside the lock is better but fine for MVP)
    auto records = healer_.handleAnomalies(anomalies);
    for (const auto& r : records) {
        if (r.action != actions::HealAction::LOG_ONLY &&
            r.action != actions::HealAction::NONE) {
            logLines_.push_back({LogEntry::INFO, "Auto-fix: " + r.description});
        }
    }
}

} // namespace fikcer::gui

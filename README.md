# FikcerAgent 

> **AI-Powered Autonomous Endpoint Management** · C++20 · macOS (Clang) / Windows (MSVC)

**FikcerAgent** is an intelligent, autonomous system agent that monitors, diagnoses, and safely resolves performance, security, and system health issues on a user's computer. Powered by Google's Gemini AI, it proactively detects anomalies, explains their root causes, and—with transparent user approval for high-risk actions—executes targeted repairs and optimizations. Designed to function as an intelligent IT technician that keeps endpoints secure, healthy, and running efficiently while maintaining full transparency and user control.

---

## 🎯 Core Capabilities

### **1. Comprehensive Anomaly Detection**

FikcerAgent continuously monitors system state and detects:

**Performance Issues:**
- CPU spikes and rapid ramps
- Memory leaks and sustained high memory usage
- Process-level resource hogs (CPU/memory)
- System overload conditions
- Disk space depletion
- Disk health warnings (SMART)
- High system temperature

**Security Threats:**
- Malware and suspicious process detection
- Firewall status monitoring
- System integrity errors
- Unauthorized driver activity

**System Health:**
- Network connectivity failures
- DNS resolution issues
- Battery status (critical alerts)
- Device driver problems

### **2. AI-Powered Root Cause Analysis**

When anomalies are detected, the Gemini AI engine:
- Analyzes the system context (CPU, memory, disk, processes, recent events)
- Determines root causes with high confidence scoring
- Classifies issue severity (low → critical)
- Assesses impact (user-facing vs. background)
- Generates detailed, plain-English explanations

### **3. Intelligent Action Planning**

The AI planner generates remediation strategies that:
- Recommend specific tools and actions from a curated skill catalog
- Assign confidence levels and risk ratings
- Explain the reasoning behind each decision
- Flag actions requiring user approval based on risk
- Learn from previous actions and outcomes

### **4. Transparent User Approval & Control**

**High-Risk Actions Require User Approval:**
- Process termination/restart
- System configuration changes
- Security-related actions
- Any action the AI assesses as requiring approval

**Transparency Features:**
- Real-time activity feed showing "What the Agent is Doing Now"
- Visible tool catalog (Monitoring, Recovery, Security, Verification skills)
- Detailed action reasoning and confidence scores
- Impact assessments for each recommended action
- Full audit trail in timestamped logs

### **5. Safe Execution & Auto-Healing**

- **Whitelist-based process management**: Only approved applications can be restarted
- **Dry-run mode**: Test all actions before execution
- **Gradual healing**: Restart limits and retry logic
- **Verification**: Confirm that executed actions succeeded

### **6. Reflection & Learning**

- **Memory persistence**: Retain insights across sessions
- **Reflection engine**: Analyze outcomes and improve future decisions
- **Goal management**: Track system health objectives
- **Health scoring**: Quantify overall endpoint health and trends

### **7. Interactive GUI Dashboard**

- **Real-time monitoring**: CPU, memory, disk, network metrics
- **Activity feed**: Color-coded event log with severity indicators
- **Gemini panel**: AI decisions, pending approvals, tool catalog
- **Security view**: Active threats and remediation status
- **Settings panel**: Configuration and mode controls (GUI/CLI)

### **8. Cross-Platform Support**

- **macOS**: Native process management, memory pressure handling, disk utilities
- **Windows**: Process control, device management, network diagnostics
- **CLI Mode**: Terminal-based operation for headless deployments

---

## 🤝 Contributing

Contributions are welcome! Whether you're fixing bugs, improving performance, adding new anomaly detectors, or expanding tool capabilities, we appreciate your help in making FikcerAgent smarter.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/meshach5667/FikcerAgent.git
cd FikcerAgent

# Build with debug symbols
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build

# Run tests (if available)
./build/FikcerAgent --cli
```

### Code Style Guidelines

- **Language**: C++20
- **Naming**: `camelCase` for functions/variables, `PascalCase` for types
- **Indentation**: 4 spaces (no tabs)
- **Memory**: No raw pointers for user data; prefer `std::unique_ptr`, `std::shared_ptr`, or stack allocation
- **Documentation**: Add docstring comments for public APIs
- **Error handling**: Exceptions or error codes consistently throughout a component

### Contribution Areas

**High Priority:**
- Expand anomaly detection heuristics (new anomaly types, detection patterns)
- Add new recovery tools (system fixes, network diagnostics)
- Improve Gemini prompt engineering for better reasoning
- Cross-platform enhancements (Linux support, Android)
- Security hardening (input validation, API key management)

**Medium Priority:**
- Performance optimization (reduce API calls, cache results)
- Better UI/UX for the GUI dashboard
- Offline mode with cached models
- Integration with other monitoring tools

**Low Priority:**
- Documentation improvements
- Code cleanup and refactoring
- Build system improvements

### Submitting Changes

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Write tests** for new functionality
4. **Update documentation** (code comments, README if needed)
5. **Build and test**: `cmake --build build && ./build/FikcerAgent --cli`
6. **Commit clearly**: Use descriptive commit messages
7. **Submit a PR** with a clear description of:
   - What problem does it solve?
   - How does it work?
   - Any breaking changes?

### Reporting Issues

Please include:
- OS and version (macOS 12.x / Windows 11, etc.)
- Build method (GUI/CLI)
- Steps to reproduce
- Expected vs. actual behavior
- Relevant log entries (from `logs/`)

---

## 📄 License

[Your License Here]

---

## 🎯 Vision

FikcerAgent represents the future of autonomous system management—where AI agents work proactively to keep endpoints secure, healthy, and performant without requiring constant user intervention. By combining heuristic anomaly detection with advanced LLM reasoning, we create a system that learns, adapts, and improves over time.

---

## Built by MESH



## Building — Incremental Steps

### Prerequisites

**macOS (primary):**
* **macOS 12+** with **Xcode Command Line Tools** (`xcode-select --install`)
* **CMake ≥ 3.20** (`brew install cmake`)

**Windows (also supported):**
* **Windows 10/11**
* **Visual Studio Community 2022** with the *Desktop development with C++*
  workload installed
* **CMake ≥ 3.20** (ships with VS 2022)

### Option A – macOS Terminal (recommended)

```bash
cd FikcerAgent.exe

# Configure (Unix Makefiles – default on macOS)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build -j$(sysctl -n hw.ncpu)

# Run
./build/FikcerAgent
```

### Option B – Visual Studio 2022 (Windows)

1. **Open folder**: *File → Open → Folder…* → select the `FikcerAgent.exe` root.
2. VS auto-detects `CMakeLists.txt` and generates the project.
3. **Build**: *Build → Build All* (or `Ctrl+Shift+B`).
4. **Run**: *Debug → Start Without Debugging* (`Ctrl+F5`).

Or from a Developer Command Prompt:

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\FikcerAgent.exe
```

---

## Configuration

All tuneable values live in [`config.h`](config.h):

### Monitoring & Detection

| Constant | Default | Purpose |
|----------|---------|---------|
| `MONITOR_INTERVAL_MS` | 5,000 ms | Interval between system stats snapshots |
| `AI_SCAN_INTERVAL_MS` | 5,000 ms | Heuristic anomaly detection frequency |
| `DEEP_SCAN_INTERVAL_MS` | 60,000 ms | Full system scan + Gemini analysis frequency |
| `CPU_WARNING_THRESHOLD` | 90% | Log alert when exceeded |
| `MEMORY_WARNING_THRESHOLD` | 90% | Log alert when exceeded |
| `PROCESS_CPU_HOG_THRESHOLD` | 80% | Single process flagged as CPU hog |
| `PROCESS_MEM_HOG_BYTES` | 2 GB | Single process flagged as memory hog |
| `CPU_RAMP_DELTA` | 15% | Rapid CPU increase threshold per sample |
| `MEMORY_LEAK_WINDOW_SAMPLES` | 12 | Samples for leak detection window |

### AI & Approval

| Constant | Default | Purpose |
|----------|---------|---------|
| `GEMINI_MODEL` | `gemini-2.0-flash` | AI model for reasoning and planning |
| `GEMINI_MAX_CALLS_PER_HOUR` | 30 | Rate limiting for Gemini API |
| `AUTO_FIX_ENABLED` | `true` | Enable automatic low-risk action execution |
| `AUTO_FIX_MAX_SEVERITY` | `"MEDIUM"` | Max severity auto-fixed without approval |
| `DRY_RUN` | `false` | Disable actual process kill/restart (log only) |

### Process Management & Healing

| Constant | Default | Purpose |
|----------|---------|---------|
| `PROCESS_SCAN_INTERVAL_MS` | 10,000 ms | Hung-process detection frequency |
| `HANG_DETECT_TIMEOUT_MS` | 5,000 ms | Window responsiveness probe timeout |
| `RESTART_DELAY_MS` | 2,000 ms | Grace period before process restart |
| `MAX_RESTART_ATTEMPTS` | 3 | Max restart attempts per process |
| `HEAL_COOLDOWN_MS` | 30,000 ms | Minimum gap between heal actions on same PID |
| `MAX_HEAL_ATTEMPTS_PER_PID` | 3 | Max total heal attempts per process |

### Logging

| Constant | Default | Purpose |
|----------|---------|---------|
| `LOG_DIRECTORY` | `logs/` | Relative directory for log files |
| `MAX_LOG_FILE_SIZE` | 5 MB | Rotate log after this size |
| `MAX_LOG_FILES` | 10 | Keep this many rotated files |
| `LOG_FILE_PREFIX` | `fikcerAgent` | Base name for log files |

---

## 🔐 Security & Approval Workflow

### Safe by Design

**Approval Workflow:**
1. **Anomaly Detected** → System snapshot captured
2. **AI Analysis** → Root cause determined, severity assessed
3. **Risk Classification** → Gemini rates action risk level
4. **Decision Point**:
   - **Low-risk, approved severity** → Auto-executed if `AUTO_FIX_ENABLED`
   - **High-risk or critical** → User approval required via GUI
5. **Execution** → Whitelisted actions only
6. **Verification** → Confirm action success and impact
7. **Learning** → Store outcomes for future decisions

### Whitelist-Based Process Management

Only processes explicitly added to the whitelist can be auto-restarted or terminated. Edit the whitelist in [`main.cpp`](main.cpp):

```cpp
// macOS
procMgr.addToWhitelist("TextEdit");
procMgr.addToWhitelist("Calculator");
procMgr.addToWhitelist("Slack");
procMgr.addToWhitelist("VirtualBuddy");

// Windows
procMgr.addToWhitelist("notepad.exe");
procMgr.addToWhitelist("explorer.exe");
procMgr.addToWhitelist("GoogleChrome.exe");
procMgr.addToWhitelist("Code.exe");
```

**Processes NOT on the whitelist** are logged as anomalies but never touched by the agent—maintaining user trust and system stability.

---

## 🧠 Skill Categories & Tool Catalog

The agent organizes remediation capabilities into four skill categories:

### **Monitoring Skills**
- `GetCPUUsage` – Current CPU utilization
- `GetMemoryUsage` – Memory and virtual memory stats
- `GetDiskUsage` – Disk space and I/O metrics
- `GetNetworkStatus` – Connection health
- `ScanProcesses` – Running application inventory

### **Recovery Skills**
- `RestartProcess` – Safely restart hung applications
- `TerminateProcess` – Force-close resource hogs
- `FlushDNS` – Resolve network issues
- `ResetNetworkAdapter` – Restore connectivity
- `ClearMemoryCache` – Relieve memory pressure

### **Security Skills**
- `QuarantineFile` – Isolate suspicious executables
- `BlockIP` – Network-level threat mitigation
- `DisableSuspiciousStartup` – Remove malware persistence
- `EnableFirewall` – Activate system firewall
- `CheckIntegrity` – Verify system files

### **Verification Skills**
- `VerifyAction` – Confirm execution success
- `GetHealthScore` – Quantify endpoint health
- `ValidateRepair` – Check issue resolution
- `MonitorOutcome` – Track post-action system state

---

## 🌐 AI Integration (Gemini API)

### Prerequisites

1. **Google Cloud Account** with Gemini API access
2. **API Key** from Google Cloud Console
   - Go to [Google AI Studio](https://aistudio.google.com/)
   - Create or copy your API key
   - Set environment variable: `export GEMINI_API_KEY="your-key-here"`

### How It Works

- Agent sends structured system context (stats, anomalies, goals, available tools)
- Gemini reasons about the situation and generates action plans in JSON
- Plans include root-cause analysis, confidence scores, and risk assessments
- Agent executes only approved, whitelisted actions
- Outcomes are stored in memory for continuous learning

### Rate Limiting & Cost Control

- Default limit: 30 API calls/hour (configurable in `config.h`)
- Model: `gemini-2.0-flash` (fast, cost-effective)
- Deep scans: Once every 60 seconds (configurable)
- Heuristic scans: Every 5 seconds (no API calls)

---

## 🏗️ Architecture

FikcerAgent implements the **Observe → Analyze → Reason → Plan → Decide → Act → Verify → Learn** loop:

```
┌─────────────────────────────────────────────────────────────────┐
│  System State (Monitor, System Scanner, Anomaly Detector)       │
│  • CPU, Memory, Disk, Network, Processes, Security Status       │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  World State & Goal Manager                                      │
│  • Track system health objectives and constraints                │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  AI Planner (Gemini Integration)                                │
│  • Build context: World state + Memory + Tools                  │
│  • Generate action plans with reasoning & risk assessment        │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Impact Classifier & Approval Manager                           │
│  • Assess severity and impact of recommended actions             │
│  • Route high-risk actions for user approval                     │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Action Executor (Auto-Healer, Process Manager, System Fixer)  │
│  • Execute approved, whitelisted actions only                   │
│  • Maintain audit trail and dry-run capability                  │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Verification & Learning                                        │
│  • Verify action success and health improvement                 │
│  • Update memory store with outcomes                            │
│  • Reflect on decisions and refine future strategies            │
└─────────────────────────────────────────────────────────────────┘
```

### Key Modules

| Module | Purpose |
|--------|---------|
| **core/** | System monitoring and state collection |
| **ai/** | Anomaly detection and Gemini integration |
| **agent/** | Orchestrator, planning, reasoning, learning |
| **actions/** | Process management and system repairs |
| **gui/** | Dear ImGui dashboard and controls |
| **utils/** | Logging, HTTP, execution, notifications |

---

## 📁 Project Structure

```
FikcerAgent/
├── CMakeLists.txt          # Build configuration
├── config.h                # Global tunable constants
├── main.cpp                # Entry point (GUI/CLI mode selector)
│
├── agent/                  # AI orchestrator and reasoning
│   ├── agent.{h,cpp}          # Main orchestrator loop
│   ├── ai_planner.{h,cpp}     # Gemini-based planning
│   ├── goal_manager.{h,cpp}   # System health goals
│   ├── world_state.{h,cpp}    # Current system state
│   ├── impact_classifier.{h,cpp} # Risk assessment
│   ├── reflection_engine.{h,cpp} # Outcome analysis
│   ├── learning_engine.{h,cpp}   # Strategy improvement
│   ├── memory_store.{h,cpp}      # Persistent insights
│   ├── tool_registry.{h,cpp}     # Tool catalog
│   └── health_score.{h,cpp}      # Endpoint health metric
│
├── ai/                     # AI detection engines
│   ├── anomaly_detector.{h,cpp}  # Heuristic + statistical detection
│   └── gemini_client.{h,cpp}     # Google Gemini API client
│
├── core/                   # System monitoring
│   ├── monitor.{h,cpp}        # CPU, memory, disk metrics
│   └── system_scanner.{h,cpp} # Deep system diagnostics
│
├── actions/                # Remediation actions
│   ├── process_manager.{h,cpp} # Process whitelist & control
│   ├── auto_healer.{h,cpp}     # Automatic repairs
│   └── system_fixer.{h,cpp}    # System-level fixes
│
├── gui/                    # Desktop interface
│   ├── app.{h,cpp}        # Main GUI application
│   └── imgui/             # Dear ImGui rendering library
│
├── utils/                  # Utility libraries
│   ├── logger.{h,cpp}       # Timestamped rotating logs
│   ├── exec.h               # OS command execution
│   ├── httplib.h            # HTTP client (Gemini API)
│   ├── notify.h             # OS notifications
│   └── imgui/               # ImGui vendored code
│
└── logs/                   # Runtime logs directory
```

---

## 🚀 Usage Modes

### GUI Mode (Default)

```bash
./build/FikcerAgent
```

Opens the desktop dashboard with:
- **Dashboard Tab**: System metrics and AI activity feed
- **Gemini Tab**: AI decisions, pending approvals, tool catalog
- **Security Tab**: Active threats and remediation status
- **Settings Tab**: Configuration and mode controls

### CLI Mode

```bash
./build/FikcerAgent --cli
```

Terminal-based operation showing:
- Real-time system stats
- Anomaly detection logs
- Execution transcript
- Dry-run preview capability

### Environment Variables

```bash
# Set your Gemini API key (required for AI features)
export GEMINI_API_KEY="your-api-key-here"

# Optional: Log level (DEBUG, INFO, WARN, ERROR)
export FIKCER_LOG_LEVEL="INFO"

# Run with specific configuration
./build/FikcerAgent --config custom_config.h
```

---

## ✅ Running the Agent

### First Time Setup

1. **Clone and build** (see [Building](#building--incremental-steps) section)
2. **Get a Gemini API key** from [Google AI Studio](https://aistudio.google.com/)
3. **Set your API key**: `export GEMINI_API_KEY="your-key"`
4. **Configure whitelist** in [`main.cpp`](main.cpp) with your trusted apps
5. **Test in dry-run mode**: Set `DRY_RUN = true` in [`config.h`](config.h)
6. **Review logs** in the `logs/` directory
7. **Run live** after validation

### Example Session

```bash
# Build
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

# Set API key
export GEMINI_API_KEY="AIzaSyC..."

# Run GUI
./build/FikcerAgent

# Or CLI
./build/FikcerAgent --cli
```

### Monitoring Output

Watch the activity feed in the GUI or tail logs in CLI:

```bash
tail -f logs/fikcerAgent_*.log
```

Example log entries:
```
[INFO] I detected: CPU spike on process Firefox (95% CPU)
[WARN] Deep scan: Malware signatures detected in 2 files
[INFO] I analyzed the situation: Browser cache causing CPU load
[INFO] AI recommended: Clear browser cache (confidence: 89%)
[PENDING] Awaiting user approval for: ClearMemoryCache on Firefox
[INFO] User approved. Executing action...
[INFO] ✓ Cache cleared successfully. CPU dropped to 45%.
```

---

## Built by MESH






# TODOs

no todos

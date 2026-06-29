# FikcerAgent 

> **Cross-platform** · C++20 · macOS (Clang) / Windows (MSVC)

FikcerAgent is a modular, console-based system agent that monitors CPU and
memory usage in real time, detects hung / unresponsive applications, and
automatically restarts whitelisted processes — all with timestamped, rotating
log files.


## contribution guidelines  
Contributions are welcome! Please fork the repo and submit a pull request with
a clear description of your changes. 

-- **Code style**: Follow the existing C++ style (camelCase, 4-space indent, no raw pointers for user data).

-- **clone repo
```bash
git clone https://github.com/meshach5667/FikcerAgent.exe.git

```
```
cd FikcerAgent.exe
```



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

| Constant | Default | Purpose |
|----------|---------|---------|
| `MONITOR_INTERVAL_MS` | 5 000 | Stats print frequency |
| `PROCESS_SCAN_INTERVAL_MS` | 10 000 | Hung-process scan frequency |
| `CPU_WARNING_THRESHOLD` | 90 % | Log a warning when exceeded |
| `MEMORY_WARNING_THRESHOLD` | 90 % | Log a warning when exceeded |
| `MAX_RESTART_ATTEMPTS` | 3 | Per-process restart cap |
| `MAX_LOG_FILE_SIZE` | 5 MB | Rotate after this size |
| `MAX_LOG_FILES` | 10 | Keep this many rotated files |
| `DRY_RUN` | `false` | Set `true` to disable kill/restart |

---

## Whitelist

Only processes explicitly added to the whitelist can be auto-restarted.
Edit the whitelist in `main.cpp`:

```cpp
// macOS
procMgr.addToWhitelist("TextEdit");
procMgr.addToWhitelist("Calculator");
procMgr.addToWhitelist("YourApp");

// Windows
procMgr.addToWhitelist("notepad.exe");
procMgr.addToWhitelist("explorer.exe");
procMgr.addToWhitelist("yourapp.exe");
```

Processes **not** on the whitelist are logged but never touched.

## Built by MESH






# TODOs

* Fix battery status - it is showing charging even when the laptop is unplugged. 
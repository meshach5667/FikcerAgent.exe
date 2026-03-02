# ============================================================================
# FikcerAgent – Autonomous Self-Healing System Agent
# CMake Build Configuration (Visual Studio 2022 / MSVC)
# ============================================================================
cmake_minimum_required(VERSION 3.20)
project(FikcerAgent
    VERSION   1.0.0
    LANGUAGES CXX
    DESCRIPTION "Autonomous self-healing Windows system agent"
)

# ── C++ Standard ────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler Flags ──────────────────────────────────────────────────────────
if(MSVC)
    # /W4   – high warning level
    # /WX   – treat warnings as errors
    # /sdl  – additional security checks
    # /GS   – buffer-overrun security checks
    # /guard:cf – control-flow guard
    # /permissive- – strict standard conformance
    add_compile_options(/W4 /WX /sdl /GS /guard:cf /permissive-)

    # Release-specific optimizations
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL /DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
else()
    # GCC/Clang for cross-compilation or CI
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -O2)
endif()

# ── Source Files ────────────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    core/monitor.cpp
    actions/process_manager.cpp
    utils/logger.cpp
)

set(HEADERS
    config.h
    core/monitor.h
    actions/process_manager.h
    utils/logger.h
)

# ── Executable ──────────────────────────────────────────────────────────────
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Include root so headers can be included as "core/monitor.h" etc.
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR})

# ── Platform Libraries ──────────────────────────────────────────────────────
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        psapi       # Process enumeration (EnumProcesses)
        user32      # IsHungAppWindow, SendMessageTimeout
        advapi32    # Security / privilege APIs
    )
    # Unicode build
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    )
endif()

# ── Install ─────────────────────────────────────────────────────────────────
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

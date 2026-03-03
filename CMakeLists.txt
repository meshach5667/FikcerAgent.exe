# ============================================================================
# FikcerAgent – Autonomous Self-Healing System Agent
# CMake Build Configuration (Visual Studio 2022 / MSVC / Xcode / Unix Makefiles)
# ============================================================================
cmake_minimum_required(VERSION 3.20)
project(FikcerAgent
    VERSION   2.0.0
    LANGUAGES CXX
    DESCRIPTION "Autonomous self-healing cross-platform system agent with GUI"
)

# ── C++ Standard ────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler Flags ──────────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4 /WX /sdl /GS /guard:cf /permissive-)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL /DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
else()
    # -Wno-deprecated-declarations silences macOS OpenGL deprecation warnings
    add_compile_options(-Wall -Wextra -Wpedantic -O2
                        -Wno-deprecated-declarations)
endif()

# ── Dear ImGui Sources ──────────────────────────────────────────────────────
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/vendor/imgui)
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

# ── Application Sources ────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    gui/app.cpp
    core/monitor.cpp
    core/system_scanner.cpp
    actions/process_manager.cpp
    actions/auto_healer.cpp
    actions/system_fixer.cpp
    ai/anomaly_detector.cpp
    ai/gemini_client.cpp
    utils/logger.cpp
)

set(HEADERS
    config.h
    gui/app.h
    core/monitor.h
    core/system_scanner.h
    actions/process_manager.h
    actions/auto_healer.h
    actions/system_fixer.h
    ai/anomaly_detector.h
    ai/gemini_client.h
    utils/logger.h
    utils/exec.h
)

# ── Executable ──────────────────────────────────────────────────────────────
add_executable(${PROJECT_NAME} ${SOURCES} ${IMGUI_SOURCES} ${HEADERS})

# Include paths: project root + Dear ImGui + ImGui backends
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

# ── GLFW ────────────────────────────────────────────────────────────────────
find_package(glfw3 3.3 REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE glfw)

# ── OpenGL ──────────────────────────────────────────────────────────────────
if(APPLE)
    find_library(OPENGL_FRAMEWORK OpenGL)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${OPENGL_FRAMEWORK})
else()
    find_package(OpenGL REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenGL::GL)
endif()

# ── Platform Libraries ──────────────────────────────────────────────────────
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        psapi user32 advapi32
    )
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    )
elseif(APPLE)
    find_library(CORE_FOUNDATION CoreFoundation)
    find_library(IO_KIT IOKit)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        ${CORE_FOUNDATION}
        ${IO_KIT}
    )
    target_compile_definitions(${PROJECT_NAME} PRIVATE _DARWIN_C_SOURCE)
endif()

# ── libcurl (Gemini API) ────────────────────────────────────────────────────
find_package(CURL REQUIRED)
target_include_directories(${PROJECT_NAME} PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CURL_LIBRARIES})

# ── Suppress warnings in Dear ImGui vendor code ────────────────────────────
if(NOT MSVC)
    set_source_files_properties(${IMGUI_SOURCES} PROPERTIES
        COMPILE_FLAGS "-w"
    )
endif()

# ── Install ─────────────────────────────────────────────────────────────────
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

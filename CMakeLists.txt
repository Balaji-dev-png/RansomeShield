cmake_minimum_required(VERSION 3.16)
project(RansomShield VERSION 0.1.0 LANGUAGES CXX)

# ── C++ Standard ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler Warnings ────────────────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion)
elseif(MSVC)
    add_compile_options(/W4)
endif()

# ── Platform Detection ────────────────────────────────────────────────────────
if(UNIX AND NOT APPLE)
    add_compile_definitions(RANSOMSHIELD_PLATFORM_LINUX)
elseif(WIN32)
    add_compile_definitions(RANSOMSHIELD_PLATFORM_WINDOWS)
endif()

# ── Agent Library ─────────────────────────────────────────────────────────────
add_library(ransomshield_agent STATIC
    agent/src/CanaryManager.cpp
    agent/src/EntropyAnalyzer.cpp
    agent/src/MitigationEngine.cpp
    agent/src/RollbackCache.cpp
)

target_include_directories(ransomshield_agent PUBLIC
    agent/include
)

# Link filesystem library (needed on older GCC/Clang)
target_link_libraries(ransomshield_agent PUBLIC
    $<$<AND:$<CXX_COMPILER_ID:GNU>,$<VERSION_LESS:$<CXX_COMPILER_VERSION>,9.0>>:stdc++fs>
)

# ── Agent Executable ──────────────────────────────────────────────────────────
add_executable(ransomshield_agent_bin
    agent/src/main.cpp
)

target_link_libraries(ransomshield_agent_bin PRIVATE
    ransomshield_agent
)

set_target_properties(ransomshield_agent_bin PROPERTIES
    OUTPUT_NAME "ransomshield-agent"
)

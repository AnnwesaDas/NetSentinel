cmake_minimum_required(VERSION 3.20)
project(netsentinel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(NETSENTINEL_ENABLE_METAL "Build the Metal GPU compute path (macOS/Apple Silicon only)" OFF)

# --- libpcap ---------------------------------------------------------------
find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR
    "libpcap not found. Install it first:\n"
    "  macOS: libpcap ships with the system (headers via Xcode Command Line Tools),\n"
    "         or 'brew install libpcap' for a newer version.\n"
    "  Linux (dev/CI only, not the real capture target): 'sudo apt-get install libpcap-dev'")
endif()

add_library(pcap::pcap UNKNOWN IMPORTED)
set_target_properties(pcap::pcap PROPERTIES
  IMPORTED_LOCATION "${PCAP_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}")

# --- threading ---------------------------------------------------------------
find_package(Threads REQUIRED)

# --- core library (everything except main(), so tests can link it) -----------
add_library(netsentinel_core
  src/capture/capture.cpp
  src/capture/parser.cpp
  src/capture/packet.cpp
  src/queue/packet_queue.cpp
  src/queue/worker_pool.cpp
  src/analysis/entropy.cpp
  src/analysis/entropy_backend.cpp
  src/analysis/signature_db.cpp
  src/analysis/alert.cpp
  src/analysis/flow_tracker.cpp
  src/analysis/analysis_engine.cpp
)
target_link_libraries(netsentinel_core PUBLIC pcap::pcap Threads::Threads)
target_include_directories(netsentinel_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(netsentinel_core PRIVATE -Wall -Wextra)

# --- Metal (macOS / Apple Silicon only) --------------------------------------
if(NETSENTINEL_ENABLE_METAL)
  if(NOT APPLE)
    message(FATAL_ERROR "NETSENTINEL_ENABLE_METAL requires macOS.")
  endif()

  include(cmake/NetsentinelShaders.cmake)

  # metal-cpp: Apple's C++ bindings for Metal/Foundation/QuartzCore, cloned
  # into third_party/ by hand (see docs/METAL_SETUP.md). Checked here so a
  # missing copy fails with instructions instead of a missing-header error.
  set(METAL_CPP_DIR "${CMAKE_SOURCE_DIR}/third_party/metal-cpp" CACHE PATH
      "Path to a metal-cpp checkout (see docs/METAL_SETUP.md)")
  if(NOT EXISTS "${METAL_CPP_DIR}/Metal/Metal.hpp")
    message(FATAL_ERROR
      "metal-cpp not found at ${METAL_CPP_DIR}.\n"
      "Download it and set it up first — see docs/METAL_SETUP.md.\n"
      "If you placed it somewhere else, pass -DMETAL_CPP_DIR=/path/to/metal-cpp.")
  endif()

  find_library(METAL_FRAMEWORK Metal REQUIRED)
  find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
  find_library(QUARTZCORE_FRAMEWORK QuartzCore REQUIRED)

  # Generated headers (embedded .metal shader sources) live under the
  # build directory, included as "netsentinel/gpu/generated/...", matching
  # this project's normal include convention.
  set(NETSENTINEL_GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")
  set(SHADER_HEADER_DIR "${NETSENTINEL_GENERATED_DIR}/netsentinel/gpu/generated")
  netsentinel_embed_shader(
    "${CMAKE_SOURCE_DIR}/shaders/vector_add.metal"
    kVectorAddShaderSource
    "${SHADER_HEADER_DIR}/vector_add_shader.hpp")
  netsentinel_embed_shader(
    "${CMAKE_SOURCE_DIR}/shaders/payload_entropy.metal"
    kPayloadEntropyShaderSource
    "${SHADER_HEADER_DIR}/payload_entropy_shader.hpp")

  # The generated headers are listed as sources so their embed steps run
  # before anything that links this library is compiled.
  add_library(netsentinel_gpu
    src/gpu/metal_context.cpp
    src/gpu/gpu_entropy_backend.cpp
    "${SHADER_HEADER_DIR}/vector_add_shader.hpp"
    "${SHADER_HEADER_DIR}/payload_entropy_shader.hpp"
  )
  target_include_directories(netsentinel_gpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${NETSENTINEL_GENERATED_DIR}
  )
  target_include_directories(netsentinel_gpu SYSTEM PUBLIC "${METAL_CPP_DIR}")
  target_link_libraries(netsentinel_gpu PUBLIC
    netsentinel_core
    ${METAL_FRAMEWORK} ${FOUNDATION_FRAMEWORK} ${QUARTZCORE_FRAMEWORK}
  )
  target_compile_options(netsentinel_gpu PRIVATE -Wall -Wextra)

  add_executable(metal_smoke_test src/gpu/vector_add_smoke_test.cpp)
  target_link_libraries(metal_smoke_test PRIVATE netsentinel_gpu)
  target_compile_options(metal_smoke_test PRIVATE -Wall -Wextra)
endif()

# --- executable ----------------------------------------------------------------
add_executable(netsentinel src/main.cpp)
target_link_libraries(netsentinel PRIVATE netsentinel_core)
target_compile_options(netsentinel PRIVATE -Wall -Wextra)
# Entropy stage on its own, CPU vs GPU (see docs/BENCHMARK.md).
add_executable(bench_entropy src/bench/bench_entropy.cpp)
target_link_libraries(bench_entropy PRIVATE netsentinel_core)
target_compile_options(bench_entropy PRIVATE -Wall -Wextra)
# Capture thread on its own: read, decode, copy, queue (see docs/BENCHMARK.md).
add_executable(bench_capture src/bench/bench_capture.cpp)
target_link_libraries(bench_capture PRIVATE netsentinel_core)
target_compile_options(bench_capture PRIVATE -Wall -Wextra)
# Worker side on its own: each rule, and how it scales with threads.
add_executable(bench_analysis src/bench/bench_analysis.cpp)
target_link_libraries(bench_analysis PRIVATE netsentinel_core)
target_compile_options(bench_analysis PRIVATE -Wall -Wextra)

if(TARGET netsentinel_gpu)
  foreach(exe netsentinel bench_entropy)
    target_link_libraries(${exe} PRIVATE netsentinel_gpu)
    target_compile_definitions(${exe} PRIVATE NETSENTINEL_HAS_METAL)
  endforeach()
endif()

# --- tests --------------------------------------------------------------------
option(NETSENTINEL_BUILD_TESTS "Build the unit tests" ON)
if(NETSENTINEL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

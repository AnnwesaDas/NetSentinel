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

# --- Metal (macOS / Apple Silicon only) --------------------------------------
if(NETSENTINEL_ENABLE_METAL)
  if(NOT APPLE)
    message(FATAL_ERROR "NETSENTINEL_ENABLE_METAL requires macOS.")
  endif()
  # metal-cpp is a headers-only vendored dependency; see docs/METAL_SETUP.md (added in Phase 4).
  # Placeholder for now — Phase 4 wires this up for real.
endif()

# --- core library (everything except main(), so tests can link it) -----------
add_library(netsentinel_core
  src/capture/capture.cpp
  src/capture/parser.cpp
  src/capture/packet.cpp
  src/queue/packet_queue.cpp
  src/queue/worker_pool.cpp
  src/analysis/entropy.cpp
  src/analysis/signature_db.cpp
  src/analysis/alert.cpp
  src/analysis/flow_tracker.cpp
  src/analysis/analysis_engine.cpp
)
target_link_libraries(netsentinel_core PUBLIC pcap::pcap Threads::Threads)
target_include_directories(netsentinel_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(netsentinel_core PRIVATE -Wall -Wextra)

# --- executable ----------------------------------------------------------------
add_executable(netsentinel src/main.cpp)
target_link_libraries(netsentinel PRIVATE netsentinel_core)
target_compile_options(netsentinel PRIVATE -Wall -Wextra)

# --- tests --------------------------------------------------------------------
option(NETSENTINEL_BUILD_TESTS "Build the unit tests" ON)
if(NETSENTINEL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

// Minimal assertion helpers + packet builders shared by the test binaries.
// Deliberately dependency-free: no GoogleTest/Catch fetch, so the tests
// build anywhere the tool itself builds (including offline).
#pragma once

#include <arpa/inet.h>

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "netsentinel/headers.hpp"
#include "netsentinel/packet_queue.hpp"

namespace nstest {

inline int g_failures = 0;
inline int g_checks = 0;

inline void check(bool condition, const char* expr, const char* file, int line) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expr);
    }
}

inline void check_eq_size(size_t actual, size_t expected, const char* expr, const char* file,
                           int line) {
    ++g_checks;
    if (actual != expected) {
        ++g_failures;
        std::fprintf(stderr, "FAIL %s:%d: %s (got %zu, expected %zu)\n", file, line, expr, actual,
                      expected);
    }
}

inline void check_near(double actual, double expected, double tolerance, const char* expr,
                        const char* file, int line) {
    ++g_checks;
    if (std::fabs(actual - expected) > tolerance) {
        ++g_failures;
        std::fprintf(stderr, "FAIL %s:%d: %s (got %f, expected %f +/- %f)\n", file, line, expr,
                      actual, expected, tolerance);
    }
}

inline int report(const char* suite) {
    std::printf("%s: %d checks, %d failure(s)\n", suite, g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#define CHECK(cond) ::nstest::check((cond), #cond, __FILE__, __LINE__)
#define CHECK_EQ_SIZE(actual, expected) \
    ::nstest::check_eq_size((actual), (expected), #actual " == " #expected, __FILE__, __LINE__)
#define CHECK_NEAR(actual, expected, tol) \
    ::nstest::check_near((actual), (expected), (tol), #actual " ~= " #expected, __FILE__, __LINE__)

// --- raw frame builders (wire format, for exercising the real parser) ---

inline std::vector<uint8_t> build_eth(uint16_t ethertype, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame(14);
    for (int i = 0; i < 6; ++i) {
        frame[i] = 0xbb;       // dst mac
        frame[6 + i] = 0xaa;   // src mac
    }
    const uint16_t net_ethertype = htons(ethertype);
    std::memcpy(frame.data() + 12, &net_ethertype, 2);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

inline std::vector<uint8_t> build_ipv4(const char* src, const char* dst, uint8_t protocol,
                                        const std::vector<uint8_t>& payload,
                                        uint8_t ihl_words = 5) {
    const size_t header_bytes = static_cast<size_t>(ihl_words) * 4;
    std::vector<uint8_t> header(header_bytes, 0);
    header[0] = static_cast<uint8_t>((4 << 4) | ihl_words);
    const uint16_t total_length = htons(static_cast<uint16_t>(header_bytes + payload.size()));
    std::memcpy(header.data() + 2, &total_length, 2);
    header[8] = 64;         // ttl
    header[9] = protocol;
    in_addr addr{};
    inet_pton(AF_INET, src, &addr);
    std::memcpy(header.data() + 12, &addr, 4);
    inet_pton(AF_INET, dst, &addr);
    std::memcpy(header.data() + 16, &addr, 4);
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

inline std::vector<uint8_t> build_tcp(uint16_t src_port, uint16_t dst_port, uint8_t flags,
                                       const std::vector<uint8_t>& payload,
                                       uint8_t data_offset_words = 5) {
    const size_t header_bytes = static_cast<size_t>(data_offset_words) * 4;
    std::vector<uint8_t> header(header_bytes, 0);
    const uint16_t net_src = htons(src_port), net_dst = htons(dst_port);
    std::memcpy(header.data(), &net_src, 2);
    std::memcpy(header.data() + 2, &net_dst, 2);
    header[12] = static_cast<uint8_t>(data_offset_words << 4);
    header[13] = flags;
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

inline std::vector<uint8_t> build_udp(uint16_t src_port, uint16_t dst_port,
                                       const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> header(8, 0);
    const uint16_t net_src = htons(src_port), net_dst = htons(dst_port);
    const uint16_t length = htons(static_cast<uint16_t>(8 + payload.size()));
    std::memcpy(header.data(), &net_src, 2);
    std::memcpy(header.data() + 2, &net_dst, 2);
    std::memcpy(header.data() + 4, &length, 2);
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

inline std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Builds a QueuedPacket directly (bypassing the parser) for flow-rule tests.
inline netsentinel::QueuedPacket make_test_packet(const char* src_ip, const char* dst_ip,
                                                   uint16_t src_port, uint16_t dst_port,
                                                   uint8_t tcp_flags, int64_t timestamp_ms,
                                                   netsentinel::Transport transport =
                                                       netsentinel::Transport::kTCP) {
    netsentinel::QueuedPacket q;
    q.meta.has_ip = true;
    in_addr addr{};
    inet_pton(AF_INET, src_ip, &addr);
    q.meta.src_ip = ntohl(addr.s_addr);
    inet_pton(AF_INET, dst_ip, &addr);
    q.meta.dst_ip = ntohl(addr.s_addr);
    q.meta.src_port = src_port;
    q.meta.dst_port = dst_port;
    q.meta.tcp_flags = tcp_flags;
    q.meta.transport = transport;
    q.meta.timestamp.tv_sec = static_cast<time_t>(timestamp_ms / 1000);
    q.meta.timestamp.tv_usec = static_cast<suseconds_t>((timestamp_ms % 1000) * 1000);
    return q;
}

}  // namespace nstest

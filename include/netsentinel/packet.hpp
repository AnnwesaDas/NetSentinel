// Decoded, byte-order-corrected summary of a captured packet. Phase 1 only
// looks at Ethernet/IP/TCP/UDP headers; payload is kept as a byte span for
// later phases (entropy, signature matching) to consume without copying.
#pragma once

#include <cstdint>
#include <ctime>
#include <string>

namespace netsentinel {

enum class Transport : uint8_t {
    kUnknown = 0,
    kTCP,
    kUDP,
    kICMP,
};

struct ParsedPacket {
    // Capture metadata
    struct timeval timestamp {};
    uint32_t capture_length = 0;  // bytes actually captured (may be < wire length)
    uint32_t wire_length = 0;     // original length on the wire

    // Ethernet
    uint8_t src_mac[6] = {};
    uint8_t dst_mac[6] = {};

    // IPv4 (host byte order, human-usable)
    bool has_ip = false;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint8_t ttl = 0;
    uint8_t ip_protocol = 0;

    // Transport
    Transport transport = Transport::kUnknown;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_flags = 0;  // only meaningful when transport == kTCP

    // Payload (points into the buffer owned by the caller for this packet's
    // lifetime only — do not retain across capture callback invocations)
    const uint8_t* payload = nullptr;
    size_t payload_length = 0;
};

std::string mac_to_string(const uint8_t mac[6]);
std::string ipv4_to_string(uint32_t host_order_ip);
std::string transport_to_string(Transport t);
std::string tcp_flags_to_string(uint8_t flags);

}  // namespace netsentinel

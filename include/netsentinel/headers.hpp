// Raw wire-format header layouts (network byte order). These are overlaid
// directly onto captured packet bytes, so field order/size/packing must
// match the actual protocol layout exactly — no parsing library involved.
#pragma once

#include <cstdint>

namespace netsentinel {

#pragma pack(push, 1)

// IEEE 802.3 / Ethernet II, 14 bytes.
struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;  // network byte order; use ntohs()
};

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;

// IPv4 fixed header, 20 bytes (options follow if ihl() > 5).
struct IPv4Header {
    uint8_t version_ihl;    // upper nibble: version, lower nibble: IHL in 32-bit words
    uint8_t dscp_ecn;
    uint16_t total_length;  // network byte order; whole datagram, header + data
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_addr;  // network byte order
    uint32_t dst_addr;  // network byte order

    [[nodiscard]] uint8_t version() const { return version_ihl >> 4; }
    [[nodiscard]] uint8_t ihl_words() const { return version_ihl & 0x0F; }
    [[nodiscard]] size_t header_bytes() const { return static_cast<size_t>(ihl_words()) * 4; }
};

constexpr uint8_t IPPROTO_ICMP_ = 1;
constexpr uint8_t IPPROTO_TCP_ = 6;
constexpr uint8_t IPPROTO_UDP_ = 17;

constexpr uint8_t kTcpFlagFin = 0x01;
constexpr uint8_t kTcpFlagSyn = 0x02;
constexpr uint8_t kTcpFlagRst = 0x04;
constexpr uint8_t kTcpFlagPsh = 0x08;
constexpr uint8_t kTcpFlagAck = 0x10;
constexpr uint8_t kTcpFlagUrg = 0x20;

// TCP fixed header, 20 bytes (options follow if data_offset() > 5).
struct TCPHeader {
    uint16_t src_port;  // network byte order
    uint16_t dst_port;  // network byte order
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;  // upper nibble: data offset in 32-bit words
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    [[nodiscard]] uint8_t data_offset_words() const { return data_offset_reserved >> 4; }
    [[nodiscard]] size_t header_bytes() const { return static_cast<size_t>(data_offset_words()) * 4; }

    [[nodiscard]] bool fin() const { return flags & kTcpFlagFin; }
    [[nodiscard]] bool syn() const { return flags & kTcpFlagSyn; }
    [[nodiscard]] bool rst() const { return flags & kTcpFlagRst; }
    [[nodiscard]] bool psh() const { return flags & kTcpFlagPsh; }
    [[nodiscard]] bool ack() const { return flags & kTcpFlagAck; }
    [[nodiscard]] bool urg() const { return flags & kTcpFlagUrg; }
};

struct UDPHeader {
    uint16_t src_port;  // network byte order
    uint16_t dst_port;  // network byte order
    uint16_t length;    // header + data, network byte order
    uint16_t checksum;
};

#pragma pack(pop)

static_assert(sizeof(EthernetHeader) == 14, "Ethernet header must be 14 bytes on the wire");
static_assert(sizeof(IPv4Header) == 20, "IPv4 fixed header must be 20 bytes on the wire");
static_assert(sizeof(TCPHeader) == 20, "TCP fixed header must be 20 bytes on the wire");
static_assert(sizeof(UDPHeader) == 8, "UDP header must be 8 bytes on the wire");

}  // namespace netsentinel

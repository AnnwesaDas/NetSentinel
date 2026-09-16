// Parser tests: the parser reads attacker-controlled bytes, so the cases
// that matter most are the malformed ones.
#include "netsentinel/parser.hpp"

#include "test_support.hpp"

using namespace netsentinel;
using namespace nstest;

namespace {

struct timeval kTs{1700000000, 0};

std::optional<ParsedPacket> parse(const std::vector<uint8_t>& frame) {
    return parse_packet(frame.data(), static_cast<uint32_t>(frame.size()),
                         static_cast<uint32_t>(frame.size()), kTs);
}

void test_well_formed_tcp() {
    auto payload = bytes("hello world");
    auto frame = build_eth(ETHERTYPE_IPV4,
                            build_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_TCP_,
                                       build_tcp(1234, 80, kTcpFlagSyn | kTcpFlagAck, payload)));
    auto pkt = parse(frame);
    CHECK(pkt.has_value());
    CHECK(pkt->has_ip);
    CHECK(pkt->transport == Transport::kTCP);
    CHECK(pkt->src_port == 1234);
    CHECK(pkt->dst_port == 80);
    CHECK(pkt->tcp_flags == (kTcpFlagSyn | kTcpFlagAck));
    CHECK(pkt->ttl == 64);
    CHECK_EQ_SIZE(pkt->payload_length, payload.size());
    CHECK(std::memcmp(pkt->payload, payload.data(), payload.size()) == 0);
    // 10.0.0.1 in host byte order
    CHECK(pkt->src_ip == 0x0A000001u);
    CHECK(pkt->dst_ip == 0x0A000002u);
}

void test_udp() {
    auto payload = bytes("dns query");
    auto frame = build_eth(ETHERTYPE_IPV4, build_ipv4("192.168.1.5", "8.8.8.8", IPPROTO_UDP_,
                                                       build_udp(5353, 53, payload)));
    auto pkt = parse(frame);
    CHECK(pkt.has_value());
    CHECK(pkt->transport == Transport::kUDP);
    CHECK(pkt->src_port == 5353);
    CHECK(pkt->dst_port == 53);
    CHECK_EQ_SIZE(pkt->payload_length, payload.size());
}

void test_ipv4_options_are_skipped() {
    // IHL=7 => 28-byte IPv4 header (8 bytes of options). The transport
    // header must be located after the options, not at a fixed offset.
    auto payload = bytes("after options");
    auto frame = build_eth(ETHERTYPE_IPV4,
                            build_ipv4("10.1.1.1", "10.1.1.2", IPPROTO_TCP_,
                                       build_tcp(999, 8080, kTcpFlagPsh, payload), /*ihl=*/7));
    auto pkt = parse(frame);
    CHECK(pkt.has_value());
    CHECK(pkt->transport == Transport::kTCP);
    CHECK(pkt->src_port == 999);
    CHECK(pkt->dst_port == 8080);
    CHECK_EQ_SIZE(pkt->payload_length, payload.size());
}

void test_tcp_options_are_skipped() {
    // data offset = 8 words => 32-byte TCP header (12 bytes of options).
    auto payload = bytes("payload past tcp options");
    auto frame = build_eth(ETHERTYPE_IPV4,
                            build_ipv4("10.2.2.1", "10.2.2.2", IPPROTO_TCP_,
                                       build_tcp(1111, 443, kTcpFlagAck, payload, /*doff=*/8)));
    auto pkt = parse(frame);
    CHECK(pkt.has_value());
    CHECK_EQ_SIZE(pkt->payload_length, payload.size());
    CHECK(std::memcmp(pkt->payload, payload.data(), payload.size()) == 0);
}

void test_non_ipv4_is_not_decoded_further() {
    auto frame = build_eth(ETHERTYPE_ARP, std::vector<uint8_t>(28, 0x00));
    auto pkt = parse(frame);
    CHECK(pkt.has_value());   // frame is still reported
    CHECK(!pkt->has_ip);      // but not decoded as IP
    CHECK(pkt->transport == Transport::kUnknown);
}

void test_runt_frame_rejected() {
    std::vector<uint8_t> frame(10, 0xff);  // shorter than an Ethernet header
    CHECK(!parse(frame).has_value());
}

void test_truncated_ip_header() {
    auto frame = build_eth(ETHERTYPE_IPV4, std::vector<uint8_t>(12, 0x45));
    auto pkt = parse(frame);
    CHECK(pkt.has_value());
    CHECK(!pkt->has_ip);  // not enough bytes for a full IPv4 header
}

void test_truncated_tcp_header() {
    // Claims TCP, but only 10 bytes of TCP header are present.
    auto frame = build_eth(ETHERTYPE_IPV4, build_ipv4("10.0.0.3", "10.0.0.4", IPPROTO_TCP_,
                                                       std::vector<uint8_t>(10, 0x00)));
    auto pkt = parse(frame);
    CHECK(pkt.has_value());
    CHECK(pkt->has_ip);                                // IP layer parsed fine
    CHECK(pkt->transport == Transport::kUnknown);      // transport refused, no OOB read
    CHECK_EQ_SIZE(pkt->payload_length, 0u);
}

void test_bogus_ihl_rejected() {
    // IHL=3 => claims a 12-byte IPv4 header, which is below the 20-byte
    // minimum. Must not be trusted.
    auto frame = build_eth(ETHERTYPE_IPV4, build_ipv4("10.0.0.5", "10.0.0.6", IPPROTO_TCP_,
                                                       build_tcp(1, 2, kTcpFlagSyn, {})));
    frame[14] = (4 << 4) | 3;  // rewrite version_ihl to an invalid IHL
    auto pkt = parse(frame);
    CHECK(pkt.has_value());
    CHECK(!pkt->has_ip);
}

void test_lying_total_length_does_not_overrun() {
    // total_length claims far more payload than was actually captured.
    auto payload = bytes("short");
    auto frame = build_eth(ETHERTYPE_IPV4,
                            build_ipv4("10.0.0.7", "10.0.0.8", IPPROTO_TCP_,
                                       build_tcp(1, 2, kTcpFlagPsh, payload)));
    const uint16_t lie = htons(60000);
    std::memcpy(frame.data() + 14 + 2, &lie, 2);
    auto pkt = parse(frame);
    CHECK(pkt.has_value());
    // Payload must be clamped to what was actually captured, not the lie.
    CHECK(pkt->payload_length <= frame.size());
    CHECK_EQ_SIZE(pkt->payload_length, payload.size());
}

void test_snaplen_truncated_payload_is_clamped() {
    auto payload = bytes("0123456789abcdef");
    auto frame = build_eth(ETHERTYPE_IPV4, build_ipv4("10.0.0.9", "10.0.0.10", IPPROTO_TCP_,
                                                       build_tcp(1, 2, kTcpFlagPsh, payload)));
    // Simulate a snaplen cut: caplen is 8 bytes shorter than the wire length.
    const uint32_t caplen = static_cast<uint32_t>(frame.size() - 8);
    auto pkt = parse_packet(frame.data(), caplen, static_cast<uint32_t>(frame.size()), kTs);
    CHECK(pkt.has_value());
    CHECK_EQ_SIZE(pkt->payload_length, payload.size() - 8);
}

}  // namespace

int main() {
    test_well_formed_tcp();
    test_udp();
    test_ipv4_options_are_skipped();
    test_tcp_options_are_skipped();
    test_non_ipv4_is_not_decoded_further();
    test_runt_frame_rejected();
    test_truncated_ip_header();
    test_truncated_tcp_header();
    test_bogus_ihl_rejected();
    test_lying_total_length_does_not_overrun();
    test_snaplen_truncated_payload_is_clamped();
    return report("parser");
}

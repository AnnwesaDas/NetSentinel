#include "netsentinel/parser.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <cstring>

#include "netsentinel/headers.hpp"

namespace netsentinel {

std::optional<ParsedPacket> parse_packet(const uint8_t* data, uint32_t caplen,
                                          uint32_t wire_length, struct timeval ts) {
    if (data == nullptr || caplen < sizeof(EthernetHeader)) {
        return std::nullopt;
    }

    ParsedPacket pkt;
    pkt.timestamp = ts;
    pkt.capture_length = caplen;
    pkt.wire_length = wire_length;

    const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
    std::memcpy(pkt.src_mac, eth->src_mac, sizeof(pkt.src_mac));
    std::memcpy(pkt.dst_mac, eth->dst_mac, sizeof(pkt.dst_mac));

    const uint16_t ethertype = ntohs(eth->ethertype);
    if (ethertype != ETHERTYPE_IPV4) {
        // Phase 1 scope is Ethernet/IPv4/TCP; ARP/IPv6/etc. frames are
        // captured but not decoded further.
        return pkt;
    }

    size_t offset = sizeof(EthernetHeader);
    if (caplen < offset + sizeof(IPv4Header)) {
        return pkt;  // truncated before a full IPv4 header
    }

    const auto* ip = reinterpret_cast<const IPv4Header*>(data + offset);
    if (ip->version() != 4) {
        return pkt;
    }

    const size_t ip_header_bytes = ip->header_bytes();
    if (ip_header_bytes < sizeof(IPv4Header) || caplen < offset + ip_header_bytes) {
        return pkt;  // malformed IHL or truncated options
    }

    pkt.has_ip = true;
    pkt.src_ip = ntohl(ip->src_addr);
    pkt.dst_ip = ntohl(ip->dst_addr);
    pkt.ttl = ip->ttl;
    pkt.ip_protocol = ip->protocol;

    const uint16_t ip_total_length = ntohs(ip->total_length);
    // The portion of the IPv4 datagram actually present in this capture,
    // clamped so a bogus total_length field can't push us past caplen.
    const size_t ip_payload_available =
        (caplen > offset + ip_header_bytes) ? (caplen - offset - ip_header_bytes) : 0;
    const size_t ip_payload_claimed =
        (ip_total_length > ip_header_bytes) ? (ip_total_length - ip_header_bytes) : 0;
    const size_t ip_payload_length = std::min(ip_payload_available, ip_payload_claimed);

    offset += ip_header_bytes;
    const uint8_t* transport_start = data + offset;

    if (ip->protocol == IPPROTO_TCP_) {
        if (caplen < offset + sizeof(TCPHeader)) {
            return pkt;  // truncated before a full TCP header
        }
        const auto* tcp = reinterpret_cast<const TCPHeader*>(transport_start);
        const size_t tcp_header_bytes = tcp->header_bytes();
        if (tcp_header_bytes < sizeof(TCPHeader) || caplen < offset + tcp_header_bytes) {
            return pkt;  // malformed data offset or truncated options
        }

        pkt.transport = Transport::kTCP;
        pkt.src_port = ntohs(tcp->src_port);
        pkt.dst_port = ntohs(tcp->dst_port);
        pkt.tcp_flags = tcp->flags;

        const size_t payload_offset = offset + tcp_header_bytes;
        if (payload_offset <= caplen) {
            pkt.payload = data + payload_offset;
            pkt.payload_length = std::min(caplen - payload_offset,
                                           ip_payload_length > tcp_header_bytes
                                               ? ip_payload_length - tcp_header_bytes
                                               : 0);
        }
    } else if (ip->protocol == IPPROTO_UDP_) {
        if (caplen < offset + sizeof(UDPHeader)) {
            return pkt;
        }
        const auto* udp = reinterpret_cast<const UDPHeader*>(transport_start);
        pkt.transport = Transport::kUDP;
        pkt.src_port = ntohs(udp->src_port);
        pkt.dst_port = ntohs(udp->dst_port);

        const size_t payload_offset = offset + sizeof(UDPHeader);
        if (payload_offset <= caplen) {
            pkt.payload = data + payload_offset;
            pkt.payload_length = std::min(caplen - payload_offset,
                                           ip_payload_length > sizeof(UDPHeader)
                                               ? ip_payload_length - sizeof(UDPHeader)
                                               : 0);
        }
    } else if (ip->protocol == IPPROTO_ICMP_) {
        pkt.transport = Transport::kICMP;
        if (offset <= caplen) {
            pkt.payload = data + offset;
            pkt.payload_length = ip_payload_length;
        }
    }

    return pkt;
}

}  // namespace netsentinel

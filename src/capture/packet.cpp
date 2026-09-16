#include "netsentinel/packet.hpp"

#include <cstdio>

#include "netsentinel/headers.hpp"

namespace netsentinel {

std::string mac_to_string(const uint8_t mac[6]) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
                  mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string ipv4_to_string(uint32_t host_order_ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (host_order_ip >> 24) & 0xFF,
                  (host_order_ip >> 16) & 0xFF, (host_order_ip >> 8) & 0xFF,
                  host_order_ip & 0xFF);
    return std::string(buf);
}

std::string transport_to_string(Transport t) {
    switch (t) {
        case Transport::kTCP:
            return "TCP";
        case Transport::kUDP:
            return "UDP";
        case Transport::kICMP:
            return "ICMP";
        default:
            return "?";
    }
}

std::string tcp_flags_to_string(uint8_t flags) {
    std::string s;
    if (flags & kTcpFlagSyn) s += "S";
    if (flags & kTcpFlagAck) s += "A";
    if (flags & kTcpFlagFin) s += "F";
    if (flags & kTcpFlagRst) s += "R";
    if (flags & kTcpFlagPsh) s += "P";
    if (flags & kTcpFlagUrg) s += "U";
    return s.empty() ? "-" : s;
}

}  // namespace netsentinel

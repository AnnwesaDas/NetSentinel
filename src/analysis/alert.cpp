#include "netsentinel/alert.hpp"

#include <cstdio>

#include "netsentinel/packet.hpp"

namespace netsentinel {

std::string anomaly_type_to_string(AnomalyType type) {
    switch (type) {
        case AnomalyType::kPortScan:
            return "PORT_SCAN";
        case AnomalyType::kHighEntropyPayload:
            return "HIGH_ENTROPY_PAYLOAD";
        case AnomalyType::kSynFlood:
            return "SYN_FLOOD";
        case AnomalyType::kSignatureMatch:
            return "SIGNATURE_MATCH";
    }
    return "UNKNOWN";
}

std::string format_alert(const Alert& alert) {
    char buf[256];
    if (alert.dst_port != 0 || alert.src_port != 0) {
        std::snprintf(buf, sizeof(buf), "[ALERT] %-21s src=%s:%u dst=%s:%u — %s",
                      anomaly_type_to_string(alert.type).c_str(),
                      ipv4_to_string(alert.src_ip).c_str(), alert.src_port,
                      ipv4_to_string(alert.dst_ip).c_str(), alert.dst_port,
                      alert.detail.c_str());
    } else {
        std::snprintf(buf, sizeof(buf), "[ALERT] %-21s src=%s — %s",
                      anomaly_type_to_string(alert.type).c_str(),
                      ipv4_to_string(alert.src_ip).c_str(), alert.detail.c_str());
    }
    return std::string(buf);
}

}  // namespace netsentinel

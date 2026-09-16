#pragma once

#include <cstdint>
#include <string>

namespace netsentinel {

enum class AnomalyType : uint8_t {
    kPortScan,
    kHighEntropyPayload,
    kSynFlood,
    kSignatureMatch,
};

struct Alert {
    AnomalyType type;
    uint32_t src_ip;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string detail;  // human-readable specifics (e.g. "14 distinct ports in 5s")
};

std::string anomaly_type_to_string(AnomalyType type);
std::string format_alert(const Alert& alert);

}  // namespace netsentinel

#include "netsentinel/analysis_engine.hpp"

#include <cstdio>

#include "netsentinel/entropy.hpp"

namespace netsentinel {

AnalysisEngine::AnalysisEngine(AlertSink sink, AnalysisConfig config)
    : sink_(std::move(sink)), config_(config), flow_tracker_(config_.flow) {}

void AnalysisEngine::analyze(const QueuedPacket& packet) {
    const auto& meta = packet.meta;

    if (packet.payload_size() >= config_.entropy_min_payload_bytes) {
        const double entropy = shannon_entropy(packet.payload_data(), packet.payload_size());
        if (entropy >= config_.entropy_threshold) {
            Alert alert;
            alert.type = AnomalyType::kHighEntropyPayload;
            alert.src_ip = meta.src_ip;
            alert.dst_ip = meta.dst_ip;
            alert.src_port = meta.src_port;
            alert.dst_port = meta.dst_port;
            char detail[96];
            std::snprintf(detail, sizeof(detail), "entropy=%.2f bits/byte over %zuB", entropy,
                          packet.payload_size());
            alert.detail = detail;
            sink_(alert);
        }
    }

    if (packet.payload_size() > 0 && signatures_.matches(packet.payload_data(), packet.payload_size())) {
        Alert alert;
        alert.type = AnomalyType::kSignatureMatch;
        alert.src_ip = meta.src_ip;
        alert.dst_ip = meta.dst_ip;
        alert.src_port = meta.src_port;
        alert.dst_port = meta.dst_port;
        alert.detail = "payload matches a known-bad signature hash";
        sink_(alert);
    }

    for (auto& alert : flow_tracker_.observe(packet)) {
        sink_(alert);
    }
}

}  // namespace netsentinel

#include "netsentinel/analysis_engine.hpp"

#include <cstdio>

namespace netsentinel {

namespace {
Alert alert_for(AnomalyType type, const QueuedPacket& packet) {
    Alert alert;
    alert.type = type;
    alert.src_ip = packet.meta.src_ip;
    alert.dst_ip = packet.meta.dst_ip;
    alert.src_port = packet.meta.src_port;
    alert.dst_port = packet.meta.dst_port;
    return alert;
}
}  // namespace

AnalysisEngine::AnalysisEngine(AlertSink sink, AnalysisConfig config,
                               std::unique_ptr<EntropyBackend> backend)
    : sink_(std::move(sink)),
      config_(config),
      backend_(backend ? std::move(backend) : std::make_unique<CpuEntropyBackend>()),
      flow_tracker_(config_.flow) {}

void AnalysisEngine::analyze_batch(const std::vector<QueuedPacket>& batch) {
    std::vector<const QueuedPacket*> eligible;
    for (const auto& packet : batch) {
        if (packet.payload_size() >= config_.entropy_min_payload_bytes) {
            eligible.push_back(&packet);
        }
    }

    // Start entropy first so a GPU backend computes it while this thread
    // runs the signature and flow rules, which don't depend on it.
    std::unique_ptr<PendingEntropy> pending;
    if (!eligible.empty()) {
        pending = backend_->start(eligible);
    }

    for (const auto& packet : batch) {
        if (packet.payload_size() > 0 &&
            signatures_.matches(packet.payload_data(), packet.payload_size())) {
            Alert alert = alert_for(AnomalyType::kSignatureMatch, packet);
            alert.detail = "payload matches a known-bad signature hash";
            sink_(alert);
        }
        for (auto& alert : flow_tracker_.observe(packet)) {
            sink_(alert);
        }
    }

    if (eligible.empty()) {
        return;
    }
    std::vector<double> entropies;
    if (pending == nullptr || !pending->wait(entropies) || entropies.size() != eligible.size()) {
        fallbacks_.fetch_add(1, std::memory_order_relaxed);
        cpu_fallback_.compute(eligible, entropies);
    }
    for (size_t i = 0; i < eligible.size(); ++i) {
        if (entropies[i] >= config_.entropy_threshold) {
            Alert alert = alert_for(AnomalyType::kHighEntropyPayload, *eligible[i]);
            char detail[96];
            std::snprintf(detail, sizeof(detail), "entropy=%.2f bits/byte over %zuB", entropies[i],
                          eligible[i]->payload_size());
            alert.detail = detail;
            sink_(alert);
        }
    }
}

}  // namespace netsentinel

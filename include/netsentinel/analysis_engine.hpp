// Wires the detection rules together. Entropy is computed per batch through
// an EntropyBackend (CPU, or GPU in Metal builds); signature matching and
// the stateful port-scan / SYN-flood rules then run per packet. Safe to call
// concurrently from every worker thread.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "netsentinel/alert.hpp"
#include "netsentinel/entropy_backend.hpp"
#include "netsentinel/flow_tracker.hpp"
#include "netsentinel/packet_queue.hpp"
#include "netsentinel/signature_db.hpp"

namespace netsentinel {

struct AnalysisConfig {
    FlowTrackerConfig flow;
    double entropy_threshold = 7.0;        // bits/byte, out of a max of 8.0
    size_t entropy_min_payload_bytes = 32;  // skip entropy check on tiny payloads (noisy)
};

class AnalysisEngine {
public:
    using AlertSink = std::function<void(const Alert&)>;

    // A null backend means the CPU one.
    AnalysisEngine(AlertSink sink, AnalysisConfig config = {},
                   std::unique_ptr<EntropyBackend> backend = nullptr);

    // Thread-safe; call once per worker batch from any worker thread.
    void analyze_batch(const std::vector<QueuedPacket>& batch);

    [[nodiscard]] std::string backend_name() const { return backend_->name(); }

    // Batches whose entropy the configured backend failed to compute and
    // that were computed on the CPU instead. Nonzero in a GPU run means the
    // GPU did not do all the work, which matters when reading a benchmark.
    [[nodiscard]] uint64_t backend_fallbacks() const { return fallbacks_.load(); }

private:
    AlertSink sink_;
    AnalysisConfig config_;
    std::unique_ptr<EntropyBackend> backend_;
    CpuEntropyBackend cpu_fallback_;
    std::atomic<uint64_t> fallbacks_{0};
    FlowTracker flow_tracker_;
    SignatureDatabase signatures_;
};

}  // namespace netsentinel

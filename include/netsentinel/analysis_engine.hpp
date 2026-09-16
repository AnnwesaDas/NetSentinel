// Wires the Phase 3 rules together: entropy + signature matching are
// stateless per-packet checks, port scan / SYN flood go through the
// concurrency-safe FlowTracker. This is the callback WorkerPool invokes
// per packet — safe to call concurrently from every worker thread.
#pragma once

#include <cstddef>
#include <functional>

#include "netsentinel/alert.hpp"
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

    AnalysisEngine(AlertSink sink, AnalysisConfig config = {});

    // Thread-safe; call once per packet from any worker thread.
    void analyze(const QueuedPacket& packet);

private:
    AlertSink sink_;
    AnalysisConfig config_;
    FlowTracker flow_tracker_;
    SignatureDatabase signatures_;
};

}  // namespace netsentinel

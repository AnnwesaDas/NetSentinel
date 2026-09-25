// AnalysisEngine batch path: the right alerts per packet, the configured
// entropy backend actually being used, and the CPU fallback when that
// backend fails.
#include "netsentinel/analysis_engine.hpp"

#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "test_support.hpp"

using namespace netsentinel;
using namespace nstest;

namespace {

QueuedPacket with_payload(const char* src_ip, uint16_t dst_port, const std::vector<uint8_t>& payload) {
    QueuedPacket q = make_test_packet(src_ip, "10.0.0.1", 40000, dst_port, kTcpFlagAck, 1000);
    q.payload = payload;
    return q;
}

std::vector<uint8_t> random_bytes(size_t n) {
    std::mt19937 rng(7);
    std::vector<uint8_t> out(n);
    for (auto& b : out) b = static_cast<uint8_t>(rng());
    return out;
}

const std::string kEicar =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

struct Collected {
    std::mutex mutex;
    std::vector<Alert> alerts;
    AnalysisEngine::AlertSink sink() {
        return [this](const Alert& a) {
            std::lock_guard<std::mutex> lock(mutex);
            alerts.push_back(a);
        };
    }
    size_t count(AnomalyType type) {
        size_t n = 0;
        for (const auto& a : alerts) n += (a.type == type);
        return n;
    }
};

std::vector<QueuedPacket> mixed_batch() {
    return {
        with_payload("10.9.0.1", 443, random_bytes(1024)),                      // high entropy
        with_payload("10.9.0.2", 80, bytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")),  // benign, 47B
        with_payload("10.9.0.3", 8080, bytes(kEicar)),                          // signature
        with_payload("10.9.0.4", 443, random_bytes(8)),  // random but under the 32-byte minimum
        with_payload("10.9.0.5", 22, {}),                                      // no payload
    };
}

// Reports every payload as maximally random, so any packet that reaches the
// backend alerts. Proves the engine uses the backend it was given.
class AlwaysRandomBackend : public EntropyBackend {
public:
    bool compute(const std::vector<const QueuedPacket*>& packets,
                 std::vector<double>& entropies) override {
        seen += packets.size();
        entropies.assign(packets.size(), 8.0);
        return true;
    }
    std::string name() const override { return "always-random"; }
    size_t seen = 0;
};

class FailingBackend : public EntropyBackend {
public:
    bool compute(const std::vector<const QueuedPacket*>&, std::vector<double>&) override {
        return false;
    }
    std::string name() const override { return "failing"; }
};

void test_cpu_batch_raises_expected_alerts() {
    Collected c;
    AnalysisEngine engine(c.sink());
    engine.analyze_batch(mixed_batch());
    CHECK_EQ_SIZE(c.count(AnomalyType::kHighEntropyPayload), 1u);
    CHECK_EQ_SIZE(c.count(AnomalyType::kSignatureMatch), 1u);
    CHECK(engine.backend_name() == "cpu");
    CHECK(engine.backend_fallbacks() == 0);

    bool entropy_alert_is_the_random_packet = false;
    for (const auto& a : c.alerts) {
        if (a.type == AnomalyType::kHighEntropyPayload) {
            entropy_alert_is_the_random_packet = (a.dst_port == 443 && a.src_port == 40000);
        }
    }
    CHECK(entropy_alert_is_the_random_packet);
}

void test_engine_uses_the_given_backend() {
    Collected c;
    auto backend = std::make_unique<AlwaysRandomBackend>();
    AlwaysRandomBackend* raw = backend.get();
    AnalysisEngine engine(c.sink(), {}, std::move(backend));
    engine.analyze_batch(mixed_batch());
    // Only the three payloads of >= 32 bytes are sent for entropy, and all
    // three alert because this backend says they are random.
    CHECK_EQ_SIZE(raw->seen, 3u);
    CHECK_EQ_SIZE(c.count(AnomalyType::kHighEntropyPayload), 3u);
    CHECK(engine.backend_name() == "always-random");
}

void test_failed_backend_falls_back_to_cpu() {
    Collected c;
    AnalysisEngine engine(c.sink(), {}, std::make_unique<FailingBackend>());
    engine.analyze_batch(mixed_batch());
    // Same alerts as the CPU path: detection must not silently stop.
    CHECK_EQ_SIZE(c.count(AnomalyType::kHighEntropyPayload), 1u);
    CHECK_EQ_SIZE(c.count(AnomalyType::kSignatureMatch), 1u);
    CHECK(engine.backend_fallbacks() == 1);
}

void test_batch_without_entropy_candidates_skips_backend() {
    Collected c;
    auto backend = std::make_unique<AlwaysRandomBackend>();
    AlwaysRandomBackend* raw = backend.get();
    AnalysisEngine engine(c.sink(), {}, std::move(backend));
    engine.analyze_batch({with_payload("10.9.0.6", 80, bytes("tiny")),
                          with_payload("10.9.0.7", 80, {})});
    CHECK_EQ_SIZE(raw->seen, 0u);
    CHECK_EQ_SIZE(c.alerts.size(), 0u);
    engine.analyze_batch({});
    CHECK_EQ_SIZE(raw->seen, 0u);
}

void test_flow_rules_still_fire_across_batches() {
    // A port scan split over several batches must still be caught: the flow
    // state lives in the engine, not in any one batch.
    Collected c;
    AnalysisEngine engine(c.sink());
    for (int b = 0; b < 4; ++b) {
        std::vector<QueuedPacket> batch;
        for (int i = 0; i < 4; ++i) {
            batch.push_back(make_test_packet("10.66.0.1", "10.0.0.1", 40000,
                                             static_cast<uint16_t>(1000 + b * 4 + i), kTcpFlagSyn,
                                             1000 + b * 40 + i * 10));
        }
        engine.analyze_batch(batch);
    }
    CHECK_EQ_SIZE(c.count(AnomalyType::kPortScan), 1u);
}

}  // namespace

int main() {
    test_cpu_batch_raises_expected_alerts();
    test_engine_uses_the_given_backend();
    test_failed_backend_falls_back_to_cpu();
    test_batch_without_entropy_candidates_skips_backend();
    test_flow_rules_still_fire_across_batches();
    return report("analysis_engine");
}

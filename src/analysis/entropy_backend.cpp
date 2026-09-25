#include "netsentinel/entropy_backend.hpp"

#include "netsentinel/entropy.hpp"

namespace netsentinel {

namespace {
class ReadyEntropy : public PendingEntropy {
public:
    explicit ReadyEntropy(std::vector<double> values) : values_(std::move(values)) {}
    bool wait(std::vector<double>& entropies) override {
        entropies = std::move(values_);
        return true;
    }

private:
    std::vector<double> values_;
};
}  // namespace

bool EntropyBackend::compute(const std::vector<const QueuedPacket*>& packets,
                             std::vector<double>& entropies) {
    auto pending = start(packets);
    return pending != nullptr && pending->wait(entropies);
}

std::unique_ptr<PendingEntropy> CpuEntropyBackend::start(
    const std::vector<const QueuedPacket*>& packets) {
    std::vector<double> values(packets.size());
    for (size_t i = 0; i < packets.size(); ++i) {
        values[i] = shannon_entropy(packets[i]->payload_data(), packets[i]->payload_size());
    }
    return std::make_unique<ReadyEntropy>(std::move(values));
}

}  // namespace netsentinel

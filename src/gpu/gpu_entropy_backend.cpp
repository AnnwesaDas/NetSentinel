#include "netsentinel/gpu/gpu_entropy_backend.hpp"

#include "netsentinel/gpu/generated/payload_entropy_shader.hpp"

namespace netsentinel::gpu {

namespace {
class GpuPending : public PendingEntropy {
public:
    explicit GpuPending(std::unique_ptr<PendingGpuEntropy> pending) : pending_(std::move(pending)) {}
    bool wait(std::vector<double>& entropies) override {
        std::vector<float> results;
        if (!pending_->wait(results)) {
            return false;
        }
        entropies.assign(results.begin(), results.end());
        return true;
    }

private:
    std::unique_ptr<PendingGpuEntropy> pending_;
};
}  // namespace

GpuEntropyBackend::GpuEntropyBackend()
    : ok_(ctx_.is_available() && ctx_.load_kernel(kPayloadEntropyShaderSource, "payload_entropy")) {}

std::string GpuEntropyBackend::name() const { return "gpu (" + ctx_.device_name() + ")"; }

std::unique_ptr<PendingEntropy> GpuEntropyBackend::start(
    const std::vector<const QueuedPacket*>& packets) {
    if (!ok_) {
        return nullptr;
    }
    std::vector<ByteSpan> payloads;
    payloads.reserve(packets.size());
    for (const QueuedPacket* packet : packets) {
        payloads.push_back({packet->payload_data(), packet->payload_size()});
    }
    auto pending = ctx_.submit_payload_entropy(payloads);
    if (pending == nullptr) {
        return nullptr;
    }
    return std::make_unique<GpuPending>(std::move(pending));
}

}  // namespace netsentinel::gpu

#include "netsentinel/gpu/gpu_entropy_backend.hpp"

#include "netsentinel/gpu/generated/payload_entropy_shader.hpp"

namespace netsentinel::gpu {

GpuEntropyBackend::GpuEntropyBackend()
    : ok_(ctx_.is_available() && ctx_.load_kernel(kPayloadEntropyShaderSource, "payload_entropy")) {}

std::string GpuEntropyBackend::name() const { return "gpu (" + ctx_.device_name() + ")"; }

bool GpuEntropyBackend::compute(const std::vector<const QueuedPacket*>& packets,
                                std::vector<double>& entropies) {
    if (!ok_) {
        return false;
    }
    PayloadBatch batch;
    for (const QueuedPacket* packet : packets) {
        batch.add(packet->payload_data(), packet->payload_size());
    }
    std::vector<float> results;
    if (!ctx_.run_payload_entropy(batch, results)) {
        return false;
    }
    entropies.assign(results.begin(), results.end());
    return true;
}

}  // namespace netsentinel::gpu

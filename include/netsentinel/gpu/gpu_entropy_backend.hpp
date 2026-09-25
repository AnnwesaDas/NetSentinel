// EntropyBackend that runs the payload_entropy Metal kernel: one GPU
// dispatch per worker batch, started by start() and collected by wait(),
// with GPU buffers pooled across dispatches. Metal builds only.
#pragma once

#include <string>
#include <vector>

#include "netsentinel/entropy_backend.hpp"
#include "netsentinel/gpu/metal_context.hpp"

namespace netsentinel::gpu {

class GpuEntropyBackend : public EntropyBackend {
public:
    // Sets up the device and compiles the kernel. Check ok() before use.
    GpuEntropyBackend();

    [[nodiscard]] bool ok() const { return ok_; }
    [[nodiscard]] std::string error() const { return ctx_.last_error(); }

    std::unique_ptr<PendingEntropy> start(const std::vector<const QueuedPacket*>& packets) override;
    [[nodiscard]] std::string name() const override;

private:
    MetalContext ctx_;
    bool ok_ = false;
};

}  // namespace netsentinel::gpu

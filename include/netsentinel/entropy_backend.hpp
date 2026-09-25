// Where payload entropy gets computed. The analysis engine hands a whole
// worker batch to a backend at once, so a GPU backend can do it in one
// dispatch; the CPU backend just loops.
//
// Computation is split into start() and wait() so a caller can do other work
// while a GPU backend runs: the engine checks signatures and flow rules for
// the batch between the two calls.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "netsentinel/packet_queue.hpp"

namespace netsentinel {

class PendingEntropy {
public:
    virtual ~PendingEntropy() = default;

    // Blocks until the results are ready and puts one entropy (bits/byte)
    // per packet, in the order given to start(), into `entropies`. Call at
    // most once. Returns false if the computation failed.
    virtual bool wait(std::vector<double>& entropies) = 0;
};

class EntropyBackend {
public:
    virtual ~EntropyBackend() = default;

    // Starts computing the Shannon entropy of each packet's payload and may
    // return before it's done. The packets only need to stay alive for the
    // duration of this call. Returns null if the computation couldn't be
    // started. Called from every worker thread at once, so implementations
    // must be thread-safe.
    virtual std::unique_ptr<PendingEntropy> start(const std::vector<const QueuedPacket*>& packets) = 0;

    [[nodiscard]] virtual std::string name() const = 0;

    // start() followed immediately by wait().
    bool compute(const std::vector<const QueuedPacket*>& packets, std::vector<double>& entropies);
};

class CpuEntropyBackend : public EntropyBackend {
public:
    // Computes everything before returning; wait() just hands the results over.
    std::unique_ptr<PendingEntropy> start(const std::vector<const QueuedPacket*>& packets) override;
    [[nodiscard]] std::string name() const override { return "cpu"; }
};

}  // namespace netsentinel

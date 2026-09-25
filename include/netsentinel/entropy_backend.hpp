// Where payload entropy gets computed. The analysis engine hands a whole
// worker batch to a backend at once, so a GPU backend can do it in one
// dispatch; the CPU backend just loops.
#pragma once

#include <string>
#include <vector>

#include "netsentinel/packet_queue.hpp"

namespace netsentinel {

class EntropyBackend {
public:
    virtual ~EntropyBackend() = default;

    // Resizes `entropies` to packets.size() and fills entropies[i] with the
    // Shannon entropy (bits/byte) of packets[i]'s payload. Called from every
    // worker thread at once, so implementations must be thread-safe.
    // Returns false if the computation failed; `entropies` is then undefined.
    virtual bool compute(const std::vector<const QueuedPacket*>& packets,
                         std::vector<double>& entropies) = 0;

    [[nodiscard]] virtual std::string name() const = 0;
};

class CpuEntropyBackend : public EntropyBackend {
public:
    bool compute(const std::vector<const QueuedPacket*>& packets,
                 std::vector<double>& entropies) override;
    [[nodiscard]] std::string name() const override { return "cpu"; }
};

}  // namespace netsentinel

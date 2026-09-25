#include "netsentinel/entropy_backend.hpp"

#include "netsentinel/entropy.hpp"

namespace netsentinel {

bool CpuEntropyBackend::compute(const std::vector<const QueuedPacket*>& packets,
                                std::vector<double>& entropies) {
    entropies.resize(packets.size());
    for (size_t i = 0; i < packets.size(); ++i) {
        entropies[i] = shannon_entropy(packets[i]->payload_data(), packets[i]->payload_size());
    }
    return true;
}

}  // namespace netsentinel

#include "netsentinel/entropy.hpp"

#include <array>
#include <cmath>

namespace netsentinel {

double shannon_entropy(const uint8_t* data, size_t length) {
    if (data == nullptr || length == 0) {
        return 0.0;
    }

    std::array<uint32_t, 256> histogram{};
    for (size_t i = 0; i < length; ++i) {
        ++histogram[data[i]];
    }

    double entropy = 0.0;
    const double total = static_cast<double>(length);
    for (const uint32_t count : histogram) {
        if (count == 0) {
            continue;
        }
        const double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

}  // namespace netsentinel

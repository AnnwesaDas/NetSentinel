// Shannon entropy over a byte buffer — used to flag payloads that look
// encrypted/compressed/random (possible C2 or exfil traffic) as opposed to
// plaintext, which has much lower per-byte entropy.
#pragma once

#include <cstddef>
#include <cstdint>

namespace netsentinel {

// Returns entropy in bits per byte, in [0.0, 8.0]. 8.0 means every byte
// value 0-255 appeared equally often (maximally random-looking); typical
// plaintext sits well under 5.0. Returns 0.0 for an empty buffer.
double shannon_entropy(const uint8_t* data, size_t length);

}  // namespace netsentinel

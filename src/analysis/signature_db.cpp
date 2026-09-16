#include "netsentinel/signature_db.hpp"

namespace netsentinel {

namespace {
constexpr uint64_t kFnvOffsetBasis = 0xcbf29ce484222325ULL;
constexpr uint64_t kFnvPrime = 0x100000001b3ULL;

// Standard EICAR antivirus test string — harmless by design, used
// industry-wide to verify signature-based detectors fire correctly.
constexpr char kEicarTestString[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
}  // namespace

uint64_t fnv1a_hash(const uint8_t* data, size_t length) {
    uint64_t hash = kFnvOffsetBasis;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= kFnvPrime;
    }
    return hash;
}

SignatureDatabase::SignatureDatabase() { add_signature(kEicarTestString); }

void SignatureDatabase::add_signature(const std::string& raw_bytes) {
    add_hash(fnv1a_hash(reinterpret_cast<const uint8_t*>(raw_bytes.data()), raw_bytes.size()));
}

void SignatureDatabase::add_hash(uint64_t hash) { known_bad_hashes_.insert(hash); }

bool SignatureDatabase::matches(const uint8_t* data, size_t length) const {
    if (data == nullptr || length == 0) {
        return false;
    }
    return known_bad_hashes_.count(fnv1a_hash(data, length)) > 0;
}

}  // namespace netsentinel

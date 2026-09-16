// Hash-based signature matching over payload bytes. Not a substring/regex
// scanner — payloads are hashed whole (FNV-1a) and compared against a set
// of known-bad hashes, which is what makes this trivially portable to a
// GPU hash comparison in Phase 4.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>

namespace netsentinel {

uint64_t fnv1a_hash(const uint8_t* data, size_t length);

class SignatureDatabase {
public:
    // Seeds a small built-in demo signature set (the EICAR antivirus test
    // string — a standard, harmless string designed specifically for
    // exercising signature-based detectors, not real malware).
    SignatureDatabase();

    void add_signature(const std::string& raw_bytes);
    void add_hash(uint64_t hash);

    [[nodiscard]] bool matches(const uint8_t* data, size_t length) const;

private:
    std::unordered_set<uint64_t> known_bad_hashes_;
};

}  // namespace netsentinel

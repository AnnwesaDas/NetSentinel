// Entropy + signature matching tests, checked against values that can be
// derived by hand rather than against whatever the implementation happens
// to produce.
#include <string>
#include <vector>

#include "netsentinel/entropy.hpp"
#include "netsentinel/signature_db.hpp"
#include "test_support.hpp"

using namespace netsentinel;
using namespace nstest;

namespace {

void test_entropy_empty_is_zero() {
    CHECK_NEAR(shannon_entropy(nullptr, 0), 0.0, 1e-9);
    std::vector<uint8_t> empty;
    CHECK_NEAR(shannon_entropy(empty.data(), 0), 0.0, 1e-9);
}

void test_entropy_single_repeated_byte_is_zero() {
    // One symbol with probability 1.0 => -1 * log2(1) = 0 bits.
    std::vector<uint8_t> data(512, 0x41);
    CHECK_NEAR(shannon_entropy(data.data(), data.size()), 0.0, 1e-9);
}

void test_entropy_two_equal_symbols_is_one_bit() {
    // Two symbols at p=0.5 each => 1 bit per byte exactly.
    std::vector<uint8_t> data;
    for (int i = 0; i < 256; ++i) {
        data.push_back(i % 2 == 0 ? 0x00 : 0xff);
    }
    CHECK_NEAR(shannon_entropy(data.data(), data.size()), 1.0, 1e-9);
}

void test_entropy_uniform_256_is_eight_bits() {
    // Every byte value exactly once => maximum entropy, 8 bits per byte.
    std::vector<uint8_t> data(256);
    for (int i = 0; i < 256; ++i) {
        data[i] = static_cast<uint8_t>(i);
    }
    CHECK_NEAR(shannon_entropy(data.data(), data.size()), 8.0, 1e-9);
}

void test_entropy_four_symbols_is_two_bits() {
    std::vector<uint8_t> data;
    for (int i = 0; i < 400; ++i) {
        data.push_back(static_cast<uint8_t>(i % 4));
    }
    CHECK_NEAR(shannon_entropy(data.data(), data.size()), 2.0, 1e-9);
}

void test_entropy_plaintext_is_well_below_threshold() {
    const std::string text =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs. "
        "How vexingly quick daft zebras jump!";
    const double e = shannon_entropy(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    CHECK(e > 3.0);  // English text isn't degenerate...
    CHECK(e < 5.5);  // ...but is nowhere near the 7.0 alert threshold
}

void test_signature_matches_eicar() {
    SignatureDatabase db;
    const std::string eicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    CHECK(db.matches(reinterpret_cast<const uint8_t*>(eicar.data()), eicar.size()));
}

void test_signature_ignores_benign_payload() {
    SignatureDatabase db;
    const std::string benign = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    CHECK(!db.matches(reinterpret_cast<const uint8_t*>(benign.data()), benign.size()));
    CHECK(!db.matches(nullptr, 0));
}

void test_signature_is_whole_payload_only() {
    // Documents a real limitation: hashing the whole payload means a
    // signature embedded inside a larger payload is NOT detected. If that
    // ever changes (e.g. rolling-window hashing), this test should flip.
    SignatureDatabase db;
    const std::string embedded =
        "prefix X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* suffix";
    CHECK(!db.matches(reinterpret_cast<const uint8_t*>(embedded.data()), embedded.size()));
}

void test_custom_signature_can_be_added() {
    SignatureDatabase db;
    const std::string custom = "totally-unique-bad-payload-marker";
    CHECK(!db.matches(reinterpret_cast<const uint8_t*>(custom.data()), custom.size()));
    db.add_signature(custom);
    CHECK(db.matches(reinterpret_cast<const uint8_t*>(custom.data()), custom.size()));
}

void test_hash_is_stable_and_distinguishes() {
    const std::string a = "aaaa", b = "aaab";
    const auto ha = fnv1a_hash(reinterpret_cast<const uint8_t*>(a.data()), a.size());
    const auto ha2 = fnv1a_hash(reinterpret_cast<const uint8_t*>(a.data()), a.size());
    const auto hb = fnv1a_hash(reinterpret_cast<const uint8_t*>(b.data()), b.size());
    CHECK(ha == ha2);
    CHECK(ha != hb);
}

}  // namespace

int main() {
    test_entropy_empty_is_zero();
    test_entropy_single_repeated_byte_is_zero();
    test_entropy_two_equal_symbols_is_one_bit();
    test_entropy_uniform_256_is_eight_bits();
    test_entropy_four_symbols_is_two_bits();
    test_entropy_plaintext_is_well_below_threshold();
    test_signature_matches_eicar();
    test_signature_ignores_benign_payload();
    test_signature_is_whole_payload_only();
    test_custom_signature_can_be_added();
    test_hash_is_stable_and_distinguishes();
    return report("analysis");
}

// Phase 4 success criterion: the GPU entropy kernel agrees with the CPU
// implementation (src/analysis/entropy.cpp) on the same input. The CPU works
// in double and the GPU in float, so values are compared within a tolerance,
// and what must match exactly is the alert decision each one leads to.
#include <algorithm>
#include <cmath>
#include <random>
#include <string>
#include <vector>

#include <thread>

#include "netsentinel/entropy.hpp"
#include "netsentinel/entropy_backend.hpp"
#include "netsentinel/gpu/generated/payload_entropy_shader.hpp"
#include "netsentinel/gpu/gpu_entropy_backend.hpp"
#include "netsentinel/gpu/metal_context.hpp"
#include "test_support.hpp"

using namespace netsentinel;
using namespace nstest;

namespace {

constexpr double kTolerance = 1e-4;

// Same rule as AnalysisEngine's defaults.
constexpr double kAlertThreshold = 7.0;
constexpr size_t kMinPayloadBytes = 32;

std::vector<std::vector<uint8_t>> build_payloads() {
    std::mt19937 rng(12345);
    std::vector<std::vector<uint8_t>> payloads;

    payloads.push_back({});                                // empty
    payloads.push_back({0x41});                            // single byte
    payloads.push_back(std::vector<uint8_t>(1500, 0x00));  // one symbol

    std::vector<uint8_t> uniform(256);
    for (int i = 0; i < 256; ++i) uniform[i] = static_cast<uint8_t>(i);
    payloads.push_back(uniform);  // every byte value once: exactly 8 bits

    std::vector<uint8_t> repeated_uniform;
    for (int r = 0; r < 16; ++r) {
        repeated_uniform.insert(repeated_uniform.end(), uniform.begin(), uniform.end());
    }
    payloads.push_back(repeated_uniform);

    std::vector<uint8_t> two_symbols(512);
    for (size_t i = 0; i < two_symbols.size(); ++i) two_symbols[i] = (i % 2) ? 0xff : 0x00;
    payloads.push_back(two_symbols);  // exactly 1 bit

    const std::string text =
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netsentinel-test\r\n\r\n";
    payloads.push_back(std::vector<uint8_t>(text.begin(), text.end()));

    // Random payloads at sizes that straddle the thread count and a full
    // Ethernet frame, up to the largest possible IPv4 payload.
    for (size_t n : {1, 2, 3, 31, 32, 64, 128, 255, 256, 257, 1460, 9000, 65535}) {
        std::vector<uint8_t> p(n);
        for (auto& b : p) b = static_cast<uint8_t>(rng());
        payloads.push_back(p);
    }

    // A realistic batch: many packets of mixed size, with alphabets of
    // varying width so entropies spread across the whole 0..8 range.
    std::uniform_int_distribution<int> length(0, 1500);
    for (int k = 0; k < 2000; ++k) {
        std::vector<uint8_t> p(length(rng));
        const unsigned alphabet = 1 + rng() % 256;
        for (auto& b : p) b = static_cast<uint8_t>(rng() % alphabet);
        payloads.push_back(p);
    }
    return payloads;
}

std::vector<gpu::ByteSpan> spans(const std::vector<std::vector<uint8_t>>& payloads, size_t begin,
                                 size_t end) {
    std::vector<gpu::ByteSpan> out;
    for (size_t i = begin; i < end; ++i) out.push_back({payloads[i].data(), payloads[i].size()});
    return out;
}

// Each payload's result is computed by its own threadgroup, the same way
// in every dispatch, so it must match bit for bit whatever else is batched
// with it.
bool matches(const std::vector<float>& results, const std::vector<float>& expected, size_t first) {
    if (first + results.size() > expected.size()) return false;
    for (size_t i = 0; i < results.size(); ++i) {
        if (results[i] != expected[first + i]) return false;
    }
    return true;
}

}  // namespace

int main() {
    gpu::MetalContext ctx;
    CHECK(ctx.is_available());
    if (!ctx.is_available()) {
        std::fprintf(stderr, "no Metal device: %s\n", ctx.last_error().c_str());
        return report("gpu_entropy");
    }
    const bool loaded = ctx.load_kernel(gpu::kPayloadEntropyShaderSource, "payload_entropy");
    CHECK(loaded);
    if (!loaded) {
        std::fprintf(stderr, "kernel load failed: %s\n", ctx.last_error().c_str());
        return report("gpu_entropy");
    }

    const auto payloads = build_payloads();
    gpu::PayloadBatch batch;
    for (const auto& p : payloads) batch.add(p.data(), p.size());

    std::vector<float> gpu_entropy;
    const bool ran = ctx.run_payload_entropy(batch, gpu_entropy);
    CHECK(ran);
    if (!ran) {
        std::fprintf(stderr, "dispatch failed: %s\n", ctx.last_error().c_str());
        return report("gpu_entropy");
    }
    CHECK_EQ_SIZE(gpu_entropy.size(), payloads.size());

    double max_error = 0.0;
    size_t alerts = 0, decision_mismatches = 0, near_threshold = 0;
    for (size_t i = 0; i < payloads.size(); ++i) {
        const double cpu = shannon_entropy(payloads[i].data(), payloads[i].size());
        const double gpu = gpu_entropy[i];
        const double error = std::fabs(cpu - gpu);
        max_error = std::max(max_error, error);
        if (error > kTolerance) {
            std::fprintf(stderr, "  payload %zu (%zu bytes): cpu=%.6f gpu=%.6f\n", i,
                         payloads[i].size(), cpu, gpu);
        }
        CHECK(error <= kTolerance);

        if (payloads[i].size() < kMinPayloadBytes) continue;
        // Within float precision of the threshold, the two paths may round
        // to opposite sides; that is float vs double, not a kernel bug.
        if (std::fabs(cpu - kAlertThreshold) <= kTolerance) {
            ++near_threshold;
            continue;
        }
        const bool cpu_alert = cpu >= kAlertThreshold;
        const bool gpu_alert = gpu >= kAlertThreshold;
        if (cpu_alert) ++alerts;
        if (cpu_alert != gpu_alert) ++decision_mismatches;
    }
    CHECK_EQ_SIZE(decision_mismatches, 0u);

    // Cases with an exact, hand-derivable answer.
    CHECK_NEAR(gpu_entropy[0], 0.0, 1e-6);  // empty
    CHECK_NEAR(gpu_entropy[1], 0.0, 1e-6);  // single byte
    CHECK_NEAR(gpu_entropy[2], 0.0, 1e-6);  // one symbol
    CHECK_NEAR(gpu_entropy[3], 8.0, 1e-5);  // uniform
    CHECK_NEAR(gpu_entropy[4], 8.0, 1e-5);  // uniform x16
    CHECK_NEAR(gpu_entropy[5], 1.0, 1e-5);  // two symbols

    // The pipeline is reusable: a second dispatch gives the same answers.
    std::vector<float> second_run;
    CHECK(ctx.run_payload_entropy(batch, second_run));
    CHECK(second_run == gpu_entropy);

    // Worker threads share one context in the real pipeline, so dispatch
    // from several threads at once; every thread must get the same answers.
    {
        constexpr int kThreads = 8;
        std::vector<std::vector<float>> results(kThreads);
        std::vector<char> ok(kThreads, 0);
        std::vector<std::thread> threads;
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&, t] {
                for (int round = 0; round < 5; ++round) {
                    ok[t] = ctx.run_payload_entropy(batch, results[t]);
                    if (!ok[t]) return;
                }
            });
        }
        for (auto& th : threads) th.join();
        for (int t = 0; t < kThreads; ++t) {
            CHECK(ok[t]);
            CHECK(results[t] == gpu_entropy);
        }
    }

    // Submitting without waiting: two dispatches in flight from one thread,
    // collected in reverse order.
    {
        const size_t half = payloads.size() / 2;
        auto first = ctx.submit_payload_entropy(spans(payloads, 0, half));
        auto second = ctx.submit_payload_entropy(spans(payloads, half, payloads.size()));
        CHECK(first != nullptr && second != nullptr);
        if (first != nullptr && second != nullptr) {
            std::vector<float> r1, r2;
            CHECK(second->wait(r2));
            CHECK(first->wait(r1));
            CHECK_EQ_SIZE(r1.size(), half);
            CHECK_EQ_SIZE(r2.size(), payloads.size() - half);
            CHECK(matches(r1, gpu_entropy, 0));
            CHECK(matches(r2, gpu_entropy, half));
        }
    }

    // Pooled buffers get reused across batch sizes: small, large (grow),
    // small again, then large again.
    for (size_t n : {size_t{3}, payloads.size(), size_t{10}, payloads.size()}) {
        auto pending = ctx.submit_payload_entropy(spans(payloads, 0, n));
        std::vector<float> results;
        CHECK(pending != nullptr && pending->wait(results));
        CHECK_EQ_SIZE(results.size(), n);
        CHECK(matches(results, gpu_entropy, 0));
    }

    // A dispatch dropped without waiting must not corrupt the next one that
    // reuses its buffers.
    {
        auto abandoned = ctx.submit_payload_entropy(spans(payloads, 0, payloads.size()));
        CHECK(abandoned != nullptr);
    }
    {
        std::vector<float> results;
        CHECK(ctx.run_payload_entropy(batch, results));
        CHECK(results == gpu_entropy);
    }

    // The backend the pipeline actually uses, against the CPU backend.
    {
        gpu::GpuEntropyBackend gpu_backend;
        CHECK(gpu_backend.ok());
        std::vector<QueuedPacket> packets(payloads.size());
        std::vector<const QueuedPacket*> pointers;
        for (size_t i = 0; i < payloads.size(); ++i) {
            packets[i].payload = payloads[i];
            pointers.push_back(&packets[i]);
        }
        std::vector<double> from_gpu, from_cpu;
        CHECK(gpu_backend.compute(pointers, from_gpu));
        CpuEntropyBackend().compute(pointers, from_cpu);
        CHECK_EQ_SIZE(from_gpu.size(), from_cpu.size());
        double backend_max_error = 0.0;
        for (size_t i = 0; i < from_cpu.size() && i < from_gpu.size(); ++i) {
            backend_max_error = std::max(backend_max_error, std::fabs(from_cpu[i] - from_gpu[i]));
        }
        CHECK(backend_max_error <= kTolerance);
    }

    // An empty batch is a no-op, not an error.
    gpu::PayloadBatch empty;
    std::vector<float> empty_out{1.0f, 2.0f};
    CHECK(ctx.run_payload_entropy(empty, empty_out));
    CHECK_EQ_SIZE(empty_out.size(), 0u);

    std::printf("gpu_entropy on %s: %zu payloads, max |cpu-gpu| = %.3g, "
                "%zu alerts, %zu decision mismatches, %zu within tolerance of threshold\n",
                ctx.device_name().c_str(), payloads.size(), max_error, alerts,
                decision_mismatches, near_threshold);
    return report("gpu_entropy");
}

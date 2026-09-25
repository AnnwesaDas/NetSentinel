// Phase 4 checkpoint: validates the device/queue/pipeline/buffer plumbing
// in isolation, on a trivial kernel, before any real detection math is
// ported to the GPU. See docs/METAL_SETUP.md for build/run instructions
// and what to report back if this fails.
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "netsentinel/gpu/generated/vector_add_shader.hpp"
#include "netsentinel/gpu/metal_context.hpp"

int main() {
    netsentinel::gpu::MetalContext ctx;
    if (!ctx.is_available()) {
        std::fprintf(stderr, "no Metal device available: %s\n", ctx.last_error().c_str());
        return EXIT_FAILURE;
    }
    std::printf("Metal device: %s\n", ctx.device_name().c_str());

    if (!ctx.load_kernel(netsentinel::gpu::kVectorAddShaderSource, "vector_add")) {
        std::fprintf(stderr, "failed to load kernel: %s\n", ctx.last_error().c_str());
        return EXIT_FAILURE;
    }

    constexpr size_t kCount = 1024;
    std::vector<float> a(kCount), b(kCount), result(kCount, 0.0f);
    for (size_t i = 0; i < kCount; ++i) {
        a[i] = static_cast<float>(i);
        b[i] = static_cast<float>(i) * 2.0f;
    }

    if (!ctx.run_vector_add(a.data(), b.data(), result.data(), kCount)) {
        std::fprintf(stderr, "GPU dispatch failed: %s\n", ctx.last_error().c_str());
        return EXIT_FAILURE;
    }

    size_t mismatches = 0;
    for (size_t i = 0; i < kCount; ++i) {
        const float expected = a[i] + b[i];
        if (std::fabs(result[i] - expected) > 1e-5f) {
            if (mismatches < 5) {
                std::fprintf(stderr, "  mismatch at [%zu]: got %f, expected %f\n", i, result[i],
                              expected);
            }
            ++mismatches;
        }
    }

    if (mismatches > 0) {
        std::fprintf(stderr, "FAIL: %zu / %zu results wrong\n", mismatches, kCount);
        return EXIT_FAILURE;
    }

    std::printf("PASS: %zu GPU-computed results matched CPU-computed expected values\n", kCount);
    return EXIT_SUCCESS;
}

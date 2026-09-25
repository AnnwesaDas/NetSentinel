// Shannon entropy of many payloads in one dispatch: one threadgroup per
// payload. Mirrors shannon_entropy() in src/analysis/entropy.cpp, which is
// the reference this is tested against.
//
// Host contract: threads per threadgroup is a power of two and <= 256
// (the reduction below halves it each step and indexes `partial` by thread).
#include <metal_stdlib>
using namespace metal;

kernel void payload_entropy(device const uchar* data [[buffer(0)]],
                            device const uint* offsets [[buffer(1)]],
                            device const uint* lengths [[buffer(2)]],
                            device float* entropies [[buffer(3)]],
                            uint payload [[threadgroup_position_in_grid]],
                            uint tid [[thread_position_in_threadgroup]],
                            uint threads [[threads_per_threadgroup]]) {
    threadgroup atomic_uint histogram[256];
    threadgroup float partial[256];

    for (uint bin = tid; bin < 256; bin += threads) {
        atomic_store_explicit(&histogram[bin], 0u, memory_order_relaxed);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Every thread in the group writes into the same 256 counters, so the
    // increments must be atomic or concurrent writes to a bin get lost.
    const uint offset = offsets[payload];
    const uint length = lengths[payload];
    for (uint i = tid; i < length; i += threads) {
        atomic_fetch_add_explicit(&histogram[data[offset + i]], 1u, memory_order_relaxed);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    float sum = 0.0f;
    if (length > 0) {
        const float total = float(length);
        for (uint bin = tid; bin < 256; bin += threads) {
            const uint count = atomic_load_explicit(&histogram[bin], memory_order_relaxed);
            if (count > 0) {
                const float p = float(count) / total;
                // precise:: because Metal compiles with fast math by default,
                // and fast log2 drifts far enough to disagree with the CPU.
                sum -= p * precise::log2(p);
            }
        }
    }
    partial[tid] = sum;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint stride = threads / 2; stride > 0; stride /= 2) {
        if (tid < stride) {
            partial[tid] += partial[tid + stride];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (tid == 0) {
        entropies[payload] = partial[0];
    }
}

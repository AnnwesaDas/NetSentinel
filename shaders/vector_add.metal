// Throwaway "hello world" compute kernel for Phase 4. Its only job is to
// validate the device/queue/pipeline/buffer plumbing before any real
// anomaly-detection math is ported to the GPU — see docs/METAL_SETUP.md.
#include <metal_stdlib>
using namespace metal;

kernel void vector_add(device const float* a [[buffer(0)]],
                        device const float* b [[buffer(1)]],
                        device float* result [[buffer(2)]],
                        uint id [[thread_position_in_grid]]) {
    result[id] = a[id] + b[id];
}

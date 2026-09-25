// Thin C++ wrapper around a Metal device/queue and a set of compute
// pipelines. The implementation lives in metal_context.cpp; this header has
// no Objective-C or metal-cpp types, so any .cpp can include it.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace netsentinel::gpu {

// Many payloads packed into one contiguous buffer, the layout the entropy
// kernel reads: payload i is bytes[offsets[i] .. offsets[i] + lengths[i]).
struct PayloadBatch {
    std::vector<uint8_t> bytes;
    std::vector<uint32_t> offsets;
    std::vector<uint32_t> lengths;

    void add(const uint8_t* data, size_t length) {
        offsets.push_back(static_cast<uint32_t>(bytes.size()));
        lengths.push_back(static_cast<uint32_t>(length));
        if (length > 0) {
            bytes.insert(bytes.end(), data, data + length);
        }
    }
    [[nodiscard]] size_t size() const { return offsets.size(); }
};

class MetalContext {
public:
    MetalContext();
    ~MetalContext();

    MetalContext(const MetalContext&) = delete;
    MetalContext& operator=(const MetalContext&) = delete;

    // False if no usable Metal device was found.
    [[nodiscard]] bool is_available() const;
    [[nodiscard]] std::string device_name() const;
    [[nodiscard]] std::string last_error() const;

    // Compiles `kernel_source` (Metal Shading Language) and builds a compute
    // pipeline for `function_name`, kept under that name. The run_* methods
    // below each need their kernel loaded first.
    //
    // Threading: load every kernel before sharing the context. After that,
    // the run_* methods may be called from several threads at once (Metal's
    // device and command queue are thread-safe; each call uses its own
    // buffers and command buffer).
    bool load_kernel(const std::string& kernel_source, const std::string& function_name);

    // Needs "vector_add" loaded. result[i] = a[i] + b[i].
    bool run_vector_add(const float* a, const float* b, float* result, size_t count);

    // Needs "payload_entropy" loaded. Writes one Shannon entropy (bits per
    // byte) per payload into `entropies`, resized to batch.size().
    bool run_payload_entropy(const PayloadBatch& batch, std::vector<float>& entropies);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace netsentinel::gpu

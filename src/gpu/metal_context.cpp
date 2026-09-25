// metal-cpp drives Metal from plain C++ (it calls the Objective-C runtime
// directly), but the *_PRIVATE_IMPLEMENTATION macros below must be defined in
// exactly one translation unit in the program. This is that one file.
#include "netsentinel/gpu/metal_context.hpp"

#define NS_PRIVATE_IMPLEMENTATION
#define CA_PRIVATE_IMPLEMENTATION
#define MTL_PRIVATE_IMPLEMENTATION
#include <Foundation/Foundation.hpp>
#include <Metal/Metal.hpp>
#include <QuartzCore/QuartzCore.hpp>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace netsentinel::gpu {

namespace {

std::string ns_error_to_string(NS::Error* error) {
    if (error == nullptr) {
        return "(no error details)";
    }
    NS::String* desc = error->localizedDescription();
    return desc != nullptr ? std::string(desc->utf8String()) : "(no description)";
}

// Scoped autorelease pool: metal-cpp calls that don't start with "new" hand
// back autoreleased objects, which are freed when the enclosing pool drains.
class PoolScope {
public:
    PoolScope() : pool_(NS::AutoreleasePool::alloc()->init()) {}
    ~PoolScope() { pool_->release(); }
    PoolScope(const PoolScope&) = delete;
    PoolScope& operator=(const PoolScope&) = delete;

private:
    NS::AutoreleasePool* pool_;
};

// Shared storage: on Apple Silicon the CPU and GPU use the same memory, so
// buffer->contents() is readable from the CPU without a copy back. Metal
// rejects zero-length buffers, hence the one-byte minimum.
NS::SharedPtr<MTL::Buffer> make_buffer(MTL::Device* device, const void* data, size_t bytes) {
    const NS::UInteger length = std::max<size_t>(bytes, 1);
    MTL::Buffer* buffer = (data != nullptr && bytes > 0)
                              ? device->newBuffer(data, length, MTL::ResourceStorageModeShared)
                              : device->newBuffer(length, MTL::ResourceStorageModeShared);
    return NS::TransferPtr(buffer);
}

// Makes `buffer` hold at least `needed` bytes. Grows geometrically, so a
// pooled buffer settles at the largest batch it has seen and then stops
// reallocating.
bool ensure_capacity(MTL::Device* device, NS::SharedPtr<MTL::Buffer>& buffer, size_t& capacity,
                     size_t needed) {
    if (buffer && capacity >= needed) {
        return true;
    }
    const size_t grown = std::max({needed, capacity * 2, size_t{4096}});
    buffer = NS::TransferPtr(device->newBuffer(grown, MTL::ResourceStorageModeShared));
    capacity = buffer ? grown : 0;
    return static_cast<bool>(buffer);
}

}  // namespace

// GPU buffers for one in-flight payload_entropy dispatch, pooled and reused.
struct EntropyBufferSet {
    NS::SharedPtr<MTL::Buffer> data, offsets, lengths, results;
    size_t data_capacity = 0, offsets_capacity = 0, lengths_capacity = 0, results_capacity = 0;
};

// Members are destroyed in reverse order, so the device outlives everything
// created from it.
struct MetalContext::Impl {
    NS::SharedPtr<MTL::Device> device;
    NS::SharedPtr<MTL::CommandQueue> queue;
    std::unordered_map<std::string, NS::SharedPtr<MTL::ComputePipelineState>> pipelines;

    // Buffer sets not currently in use by a dispatch.
    std::mutex pool_mutex;
    std::vector<std::unique_ptr<EntropyBufferSet>> free_buffers;

    // Guarded: run_* calls on different threads can fail at the same time.
    mutable std::mutex error_mutex;
    std::string last_error;

    std::unique_ptr<EntropyBufferSet> take_buffers() {
        std::lock_guard<std::mutex> lock(pool_mutex);
        if (free_buffers.empty()) {
            return std::make_unique<EntropyBufferSet>();
        }
        auto buffers = std::move(free_buffers.back());
        free_buffers.pop_back();
        return buffers;
    }

    void return_buffers(std::unique_ptr<EntropyBufferSet> buffers) {
        if (buffers) {
            std::lock_guard<std::mutex> lock(pool_mutex);
            free_buffers.push_back(std::move(buffers));
        }
    }

    void set_error(std::string message) {
        std::lock_guard<std::mutex> lock(error_mutex);
        last_error = std::move(message);
    }

    MTL::ComputePipelineState* pipeline(const std::string& name) {
        auto it = pipelines.find(name);
        if (it == pipelines.end()) {
            set_error("kernel '" + name + "' not loaded — call load_kernel() first");
            return nullptr;
        }
        return it->second.get();
    }

    // Commits `cmd`, blocks until the GPU finishes, and reports failure.
    bool submit_and_wait(MTL::CommandBuffer* cmd) {
        cmd->commit();
        cmd->waitUntilCompleted();
        if (cmd->status() != MTL::CommandBufferStatusCompleted) {
            set_error("GPU command buffer did not complete: " + ns_error_to_string(cmd->error()));
            return false;
        }
        return true;
    }
};

MetalContext::MetalContext() : impl_(std::make_unique<Impl>()) {
    PoolScope pool;
    impl_->device = NS::TransferPtr(MTL::CreateSystemDefaultDevice());
    if (!impl_->device) {
        impl_->set_error("MTL::CreateSystemDefaultDevice() returned null — no Metal-capable GPU found");
        return;
    }
    impl_->queue = NS::TransferPtr(impl_->device->newCommandQueue());
    if (!impl_->queue) {
        impl_->set_error("device->newCommandQueue() returned null");
    }
}

MetalContext::~MetalContext() = default;

bool MetalContext::is_available() const { return impl_->device && impl_->queue; }

std::string MetalContext::device_name() const {
    if (!impl_->device) {
        return "(none)";
    }
    PoolScope pool;
    NS::String* name = impl_->device->name();
    return name != nullptr ? std::string(name->utf8String()) : "(unnamed)";
}

std::string MetalContext::last_error() const {
    std::lock_guard<std::mutex> lock(impl_->error_mutex);
    return impl_->last_error;
}

bool MetalContext::load_kernel(const std::string& kernel_source,
                                const std::string& function_name) {
    if (!is_available()) {
        impl_->set_error("no Metal device available");
        return false;
    }
    PoolScope pool;

    NS::Error* error = nullptr;
    auto options = NS::TransferPtr(MTL::CompileOptions::alloc()->init());
    auto library = NS::TransferPtr(impl_->device->newLibrary(
        NS::String::string(kernel_source.c_str(), NS::UTF8StringEncoding), options.get(), &error));
    if (!library) {
        impl_->set_error("shader compile failed: " + ns_error_to_string(error));
        return false;
    }

    auto function = NS::TransferPtr(
        library->newFunction(NS::String::string(function_name.c_str(), NS::UTF8StringEncoding)));
    if (!function) {
        impl_->set_error("kernel function '" + function_name + "' not found in the compiled library");
        return false;
    }

    // The pipeline doesn't need the library or function once built, so both
    // are released when this call returns.
    auto pipeline = NS::TransferPtr(impl_->device->newComputePipelineState(function.get(), &error));
    if (!pipeline) {
        impl_->set_error("failed to build compute pipeline: " + ns_error_to_string(error));
        return false;
    }

    impl_->pipelines[function_name] = std::move(pipeline);
    return true;
}

bool MetalContext::run_vector_add(const float* a, const float* b, float* result, size_t count) {
    MTL::ComputePipelineState* pipeline = impl_->pipeline("vector_add");
    if (pipeline == nullptr) {
        return false;
    }
    if (count == 0) {
        return true;
    }
    PoolScope pool;

    const size_t bytes = count * sizeof(float);
    auto buf_a = make_buffer(impl_->device.get(), a, bytes);
    auto buf_b = make_buffer(impl_->device.get(), b, bytes);
    auto buf_out = make_buffer(impl_->device.get(), nullptr, bytes);
    if (!buf_a || !buf_b || !buf_out) {
        impl_->set_error("failed to allocate GPU buffers");
        return false;
    }

    MTL::CommandBuffer* cmd = impl_->queue->commandBuffer();
    MTL::ComputeCommandEncoder* encoder = cmd->computeCommandEncoder();
    encoder->setComputePipelineState(pipeline);
    encoder->setBuffer(buf_a.get(), 0, 0);
    encoder->setBuffer(buf_b.get(), 0, 1);
    encoder->setBuffer(buf_out.get(), 0, 2);
    const NS::UInteger width = std::min<NS::UInteger>(pipeline->maxTotalThreadsPerThreadgroup(), count);
    encoder->dispatchThreads(MTL::Size(count, 1, 1), MTL::Size(width, 1, 1));
    encoder->endEncoding();

    if (!impl_->submit_and_wait(cmd)) {
        return false;
    }
    std::memcpy(result, buf_out->contents(), bytes);
    return true;
}

struct PendingGpuEntropy::State {
    std::unique_ptr<EntropyBufferSet> buffers;
    NS::SharedPtr<MTL::CommandBuffer> command;  // null when there was nothing to dispatch
    size_t count = 0;
    bool waited = false;
};

PendingGpuEntropy::PendingGpuEntropy(MetalContext& context, std::unique_ptr<State> state)
    : context_(context), state_(std::move(state)) {}

PendingGpuEntropy::~PendingGpuEntropy() {
    if (state_->command && !state_->waited) {
        PoolScope pool;
        state_->command->waitUntilCompleted();
    }
    state_->command.reset();
    context_.impl_->return_buffers(std::move(state_->buffers));
}

bool PendingGpuEntropy::wait(std::vector<float>& entropies) {
    state_->waited = true;
    if (!state_->command) {
        entropies.clear();
        return true;
    }
    PoolScope pool;
    state_->command->waitUntilCompleted();
    if (state_->command->status() != MTL::CommandBufferStatusCompleted) {
        context_.impl_->set_error("GPU command buffer did not complete: " +
                                  ns_error_to_string(state_->command->error()));
        return false;
    }
    const auto* results = static_cast<const float*>(state_->buffers->results->contents());
    entropies.assign(results, results + state_->count);
    return true;
}

std::unique_ptr<PendingGpuEntropy> MetalContext::submit_payload_entropy(
    const std::vector<ByteSpan>& payloads) {
    MTL::ComputePipelineState* pipeline = impl_->pipeline("payload_entropy");
    if (pipeline == nullptr) {
        return nullptr;
    }
    auto state = std::make_unique<PendingGpuEntropy::State>();
    state->buffers = impl_->take_buffers();
    state->count = payloads.size();
    if (payloads.empty()) {
        return std::unique_ptr<PendingGpuEntropy>(new PendingGpuEntropy(*this, std::move(state)));
    }
    PoolScope pool;

    const size_t count = payloads.size();
    size_t total_bytes = 0;
    for (const auto& payload : payloads) {
        total_bytes += payload.size;
    }
    MTL::Device* device = impl_->device.get();
    EntropyBufferSet& b = *state->buffers;
    if (!ensure_capacity(device, b.data, b.data_capacity, total_bytes) ||
        !ensure_capacity(device, b.offsets, b.offsets_capacity, count * sizeof(uint32_t)) ||
        !ensure_capacity(device, b.lengths, b.lengths_capacity, count * sizeof(uint32_t)) ||
        !ensure_capacity(device, b.results, b.results_capacity, count * sizeof(float))) {
        impl_->set_error("failed to allocate GPU buffers");
        impl_->return_buffers(std::move(state->buffers));
        return nullptr;
    }

    // Shared storage: these writes land directly in memory the GPU reads, so
    // each payload is copied exactly once, straight from the packet.
    auto* data = static_cast<uint8_t*>(b.data->contents());
    auto* offsets = static_cast<uint32_t*>(b.offsets->contents());
    auto* lengths = static_cast<uint32_t*>(b.lengths->contents());
    size_t offset = 0;
    for (size_t i = 0; i < count; ++i) {
        offsets[i] = static_cast<uint32_t>(offset);
        lengths[i] = static_cast<uint32_t>(payloads[i].size);
        if (payloads[i].size > 0) {
            std::memcpy(data + offset, payloads[i].data, payloads[i].size);
        }
        offset += payloads[i].size;
    }

    // The kernel's reduction needs a power-of-two group of at most 256
    // threads (one per histogram bin at most).
    NS::UInteger threads = 256;
    while (threads > pipeline->maxTotalThreadsPerThreadgroup()) {
        threads /= 2;
    }

    MTL::CommandBuffer* cmd = impl_->queue->commandBuffer();
    if (cmd == nullptr) {
        impl_->set_error("queue->commandBuffer() returned null");
        impl_->return_buffers(std::move(state->buffers));
        return nullptr;
    }
    MTL::ComputeCommandEncoder* encoder = cmd->computeCommandEncoder();
    encoder->setComputePipelineState(pipeline);
    encoder->setBuffer(b.data.get(), 0, 0);
    encoder->setBuffer(b.offsets.get(), 0, 1);
    encoder->setBuffer(b.lengths.get(), 0, 2);
    encoder->setBuffer(b.results.get(), 0, 3);
    encoder->dispatchThreadgroups(MTL::Size(count, 1, 1), MTL::Size(threads, 1, 1));
    encoder->endEncoding();
    cmd->commit();

    // The command buffer is autoreleased and this pool drains on return, so
    // take our own reference for wait() to use.
    state->command = NS::RetainPtr(cmd);
    return std::unique_ptr<PendingGpuEntropy>(new PendingGpuEntropy(*this, std::move(state)));
}

bool MetalContext::run_payload_entropy(const PayloadBatch& batch, std::vector<float>& entropies) {
    std::vector<ByteSpan> payloads;
    payloads.reserve(batch.size());
    for (size_t i = 0; i < batch.size(); ++i) {
        payloads.push_back({batch.bytes.data() + batch.offsets[i], batch.lengths[i]});
    }
    auto pending = submit_payload_entropy(payloads);
    return pending != nullptr && pending->wait(entropies);
}

}  // namespace netsentinel::gpu

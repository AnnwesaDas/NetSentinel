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

}  // namespace

// Members are destroyed in reverse order, so the device outlives everything
// created from it.
struct MetalContext::Impl {
    NS::SharedPtr<MTL::Device> device;
    NS::SharedPtr<MTL::CommandQueue> queue;
    std::unordered_map<std::string, NS::SharedPtr<MTL::ComputePipelineState>> pipelines;

    // Guarded: run_* calls on different threads can fail at the same time.
    mutable std::mutex error_mutex;
    std::string last_error;

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

bool MetalContext::run_payload_entropy(const PayloadBatch& batch, std::vector<float>& entropies) {
    MTL::ComputePipelineState* pipeline = impl_->pipeline("payload_entropy");
    if (pipeline == nullptr) {
        return false;
    }
    const size_t count = batch.size();
    entropies.assign(count, 0.0f);
    if (count == 0) {
        return true;
    }
    PoolScope pool;

    auto buf_data = make_buffer(impl_->device.get(), batch.bytes.data(), batch.bytes.size());
    auto buf_offsets =
        make_buffer(impl_->device.get(), batch.offsets.data(), count * sizeof(uint32_t));
    auto buf_lengths =
        make_buffer(impl_->device.get(), batch.lengths.data(), count * sizeof(uint32_t));
    auto buf_out = make_buffer(impl_->device.get(), nullptr, count * sizeof(float));
    if (!buf_data || !buf_offsets || !buf_lengths || !buf_out) {
        impl_->set_error("failed to allocate GPU buffers");
        return false;
    }

    // The kernel's reduction needs a power-of-two group of at most 256
    // threads (one per histogram bin at most).
    NS::UInteger threads = 256;
    while (threads > pipeline->maxTotalThreadsPerThreadgroup()) {
        threads /= 2;
    }

    MTL::CommandBuffer* cmd = impl_->queue->commandBuffer();
    MTL::ComputeCommandEncoder* encoder = cmd->computeCommandEncoder();
    encoder->setComputePipelineState(pipeline);
    encoder->setBuffer(buf_data.get(), 0, 0);
    encoder->setBuffer(buf_offsets.get(), 0, 1);
    encoder->setBuffer(buf_lengths.get(), 0, 2);
    encoder->setBuffer(buf_out.get(), 0, 3);
    encoder->dispatchThreadgroups(MTL::Size(count, 1, 1), MTL::Size(threads, 1, 1));
    encoder->endEncoding();

    if (!impl_->submit_and_wait(cmd)) {
        return false;
    }
    std::memcpy(entropies.data(), buf_out->contents(), count * sizeof(float));
    return true;
}

}  // namespace netsentinel::gpu

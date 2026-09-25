// Fixed-size pool of worker threads, each draining batches from a
// PacketQueue and handing every batch to one analysis callback. Batches
// rather than single packets, so a GPU backend can process one per dispatch.
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <thread>
#include <vector>

#include "netsentinel/packet_queue.hpp"

namespace netsentinel {

class WorkerPool {
public:
    using AnalysisFn = std::function<void(const std::vector<QueuedPacket>&)>;

    // `linger` is how long a worker waits for a full batch (see
    // PacketQueue::pop_batch); it bounds the latency batching adds.
    WorkerPool(size_t num_workers, PacketQueue& queue, AnalysisFn analyze,
               size_t batch_size = 64,
               std::chrono::milliseconds poll_timeout = std::chrono::milliseconds(100),
               std::chrono::microseconds linger = std::chrono::microseconds(2000));
    ~WorkerPool();

    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;

    // Spawns the worker threads. Call once.
    void start();

    // Blocks until every worker has exited (i.e. queue_.is_finished()).
    void join();

    [[nodiscard]] uint64_t processed_count() const { return processed_.load(); }
    // Batches actually handed to the callback. processed / batches is the
    // real average batch size, which can be far below the configured max.
    [[nodiscard]] uint64_t batch_count() const { return batches_.load(); }

private:
    void worker_loop();

    PacketQueue& queue_;
    AnalysisFn analyze_;
    size_t batch_size_;
    std::chrono::milliseconds poll_timeout_;
    std::chrono::microseconds linger_;
    size_t num_workers_;
    std::vector<std::thread> threads_;
    std::atomic<uint64_t> processed_{0};
    std::atomic<uint64_t> batches_{0};
};

}  // namespace netsentinel

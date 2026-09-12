// Fixed-size pool of worker threads consuming batches from a PacketQueue.
// Phase 2 scope: just draining the queue and invoking an analysis callback
// per packet. The callback is a stand-in for Phase 3's real anomaly rules.
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
    using AnalysisFn = std::function<void(const QueuedPacket&)>;

    WorkerPool(size_t num_workers, PacketQueue& queue, AnalysisFn analyze,
               size_t batch_size = 64,
               std::chrono::milliseconds poll_timeout = std::chrono::milliseconds(100));
    ~WorkerPool();

    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;

    // Spawns the worker threads. Call once.
    void start();

    // Blocks until every worker has exited (i.e. queue_.is_finished()).
    void join();

    [[nodiscard]] uint64_t processed_count() const { return processed_.load(); }

private:
    void worker_loop();

    PacketQueue& queue_;
    AnalysisFn analyze_;
    size_t batch_size_;
    std::chrono::milliseconds poll_timeout_;
    size_t num_workers_;
    std::vector<std::thread> threads_;
    std::atomic<uint64_t> processed_{0};
};

}  // namespace netsentinel

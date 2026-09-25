#include "netsentinel/worker_pool.hpp"

namespace netsentinel {

WorkerPool::WorkerPool(size_t num_workers, PacketQueue& queue, AnalysisFn analyze,
                        size_t batch_size, std::chrono::milliseconds poll_timeout,
                        std::chrono::microseconds linger)
    : queue_(queue),
      analyze_(std::move(analyze)),
      batch_size_(batch_size),
      poll_timeout_(poll_timeout),
      linger_(linger),
      num_workers_(num_workers == 0 ? 1 : num_workers) {}

WorkerPool::~WorkerPool() { join(); }

void WorkerPool::start() {
    threads_.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; ++i) {
        threads_.emplace_back(&WorkerPool::worker_loop, this);
    }
}

void WorkerPool::join() {
    for (auto& t : threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    threads_.clear();
}

void WorkerPool::worker_loop() {
    while (true) {
        auto batch = queue_.pop_batch(batch_size_, poll_timeout_, linger_);
        if (!batch.empty()) {
            analyze_(batch);
            processed_.fetch_add(batch.size(), std::memory_order_relaxed);
            batches_.fetch_add(1, std::memory_order_relaxed);
        } else if (queue_.is_finished()) {
            break;
        }
    }
}

}  // namespace netsentinel

#include "netsentinel/packet_queue.hpp"

#include <algorithm>

namespace netsentinel {

namespace {
uint64_t elapsed_ns(std::chrono::steady_clock::time_point start) {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     std::chrono::steady_clock::now() - start)
                                     .count());
}
}  // namespace

QueuedPacket make_queued_packet(const ParsedPacket& parsed) {
    QueuedPacket q;
    q.meta = parsed;
    q.meta.payload = nullptr;
    q.meta.payload_length = 0;
    if (parsed.payload != nullptr && parsed.payload_length > 0) {
        q.payload.assign(parsed.payload, parsed.payload + parsed.payload_length);
    }
    return q;
}

PacketQueue::PacketQueue(size_t capacity) : capacity_(capacity) {}

bool PacketQueue::push(QueuedPacket packet) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (items_.size() >= capacity_ && !shutdown_) {
        // Only timed when it has to wait, so the common path stays free of
        // clock reads (this runs once per packet).
        const auto start = std::chrono::steady_clock::now();
        not_full_.wait(lock, [this] { return items_.size() < capacity_ || shutdown_; });
        push_wait_ns_.fetch_add(elapsed_ns(start), std::memory_order_relaxed);
    }

    if (shutdown_) {
        return false;
    }

    items_.push(std::move(packet));
    const size_t size = items_.size();
    const bool wake = size == 1 || size == wanted_;
    lock.unlock();
    if (wake) {
        not_empty_.notify_one();
    }
    return true;
}

std::vector<QueuedPacket> PacketQueue::pop_batch(size_t max_n, std::chrono::milliseconds timeout,
                                                 std::chrono::microseconds linger) {
    const auto start = std::chrono::steady_clock::now();
    std::unique_lock<std::mutex> lock(mutex_);
    wanted_ = max_n;
    not_empty_.wait_for(lock, timeout, [this] { return !items_.empty() || shutdown_; });

    if (!items_.empty() && items_.size() < max_n && !shutdown_ && linger.count() > 0) {
        not_empty_.wait_for(lock, linger,
                            [this, max_n] { return items_.size() >= max_n || shutdown_; });
    }

    pop_wait_ns_.fetch_add(elapsed_ns(start), std::memory_order_relaxed);

    std::vector<QueuedPacket> batch;
    const size_t n = std::min(max_n, items_.size());
    batch.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        batch.push_back(std::move(items_.front()));
        items_.pop();
    }
    const bool more_waiting = !items_.empty();
    lock.unlock();

    if (n > 0) {
        not_full_.notify_all();
    }
    // push() only wakes one consumer per batch, so if packets are left over
    // after this batch, hand off to another consumer rather than leave them
    // until that consumer's next timeout.
    if (more_waiting) {
        not_empty_.notify_one();
    }
    return batch;
}

void PacketQueue::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
    }
    not_full_.notify_all();
    not_empty_.notify_all();
}

bool PacketQueue::is_finished() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return shutdown_ && items_.empty();
}

size_t PacketQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return items_.size();
}

double PacketQueue::push_wait_seconds() const { return push_wait_ns_.load() / 1e9; }

double PacketQueue::pop_wait_seconds() const { return pop_wait_ns_.load() / 1e9; }

}  // namespace netsentinel

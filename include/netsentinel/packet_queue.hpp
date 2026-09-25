// Bounded, thread-safe producer-consumer queue between the capture thread
// and the worker pool. Design (locked in for Phase 2):
//   - mutex + condition variable, not lock-free (correctness first; a
//     lock-free queue is a stretch goal for after the Metal port).
//   - bounded capacity with backpressure: push() blocks while full rather
//     than dropping packets, so an overloaded system slows capture instead
//     of losing potential anomalies.
//   - batched pop: workers drain up to max_n packets per call, not one at
//     a time, so Phase 4's Metal port only changes the analysis step.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>
#include <vector>

#include "netsentinel/packet.hpp"

namespace netsentinel {

// A parsed packet that owns its payload bytes, safe to hand across threads.
// `meta.payload`/`meta.payload_length` are not used here — use payload_data()
// / payload_size() instead, since the pcap-owned buffer ParsedPacket::payload
// pointed to is only valid for the duration of the capture callback.
struct QueuedPacket {
    ParsedPacket meta;
    std::vector<uint8_t> payload;

    [[nodiscard]] const uint8_t* payload_data() const { return payload.data(); }
    [[nodiscard]] size_t payload_size() const { return payload.size(); }
};

QueuedPacket make_queued_packet(const ParsedPacket& parsed);

class PacketQueue {
public:
    explicit PacketQueue(size_t capacity);

    // Blocks until space is available or the queue is shut down. Returns
    // false (packet not enqueued) only if shutdown() was called first —
    // that should never happen while the capture thread is still running.
    bool push(QueuedPacket packet);

    // Blocks until at least one packet is available, `timeout` elapses, or
    // the queue is shut down, then drains up to `max_n` packets. Returning
    // an empty batch does not by itself mean the source is done — check
    // is_finished() to distinguish "idle, keep polling" from "shut down and
    // drained".
    //
    // `linger`: if fewer than `max_n` packets are waiting, wait up to this
    // long for a full batch before taking what's there. Without it, workers
    // that are faster than the producer each grab ~1 packet per call, and
    // batching (and any GPU dispatch per batch) degenerates to per-packet.
    std::vector<QueuedPacket> pop_batch(size_t max_n, std::chrono::milliseconds timeout,
                                        std::chrono::microseconds linger =
                                            std::chrono::microseconds(0));

    // Signals that no more packets will be pushed. Wakes any blocked
    // push()/pop_batch() callers. Safe to call once, after the producer
    // thread has been joined.
    void shutdown();

    // True once shutdown() has been called and every queued packet has
    // been drained by pop_batch() — the signal for workers to exit.
    [[nodiscard]] bool is_finished() const;

    [[nodiscard]] size_t size() const;

    // Total time push() callers spent blocked because the queue was full,
    // and pop_batch() callers spent waiting for packets (including the lock
    // and any linger). Together they show which side of the queue waits on
    // the other: a producer that is often blocked means the consumers are
    // the bottleneck, and consumers that are often waiting mean the producer
    // is.
    [[nodiscard]] double push_wait_seconds() const;
    [[nodiscard]] double pop_wait_seconds() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable not_full_;
    std::condition_variable not_empty_;
    std::queue<QueuedPacket> items_;
    size_t capacity_;
    // Batch size consumers last asked for. push() wakes a consumer only when
    // the queue becomes non-empty or reaches this size, not on every packet.
    size_t wanted_ = 1;
    bool shutdown_ = false;
    std::atomic<uint64_t> push_wait_ns_{0};
    std::atomic<uint64_t> pop_wait_ns_{0};
};

}  // namespace netsentinel

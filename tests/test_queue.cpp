// Queue tests, including the concurrent behaviour the Phase 2 design
// promises: FIFO order, backpressure instead of dropping, and a shutdown
// that drains rather than discards.
#include "netsentinel/packet_queue.hpp"

#include <atomic>
#include <chrono>
#include <thread>

#include "test_support.hpp"

using namespace netsentinel;
using namespace nstest;

namespace {

QueuedPacket packet_with_id(uint16_t id) {
    QueuedPacket q;
    q.meta.has_ip = true;
    q.meta.src_port = id;
    return q;
}

void test_batch_pop_preserves_fifo_order() {
    PacketQueue queue(100);
    for (uint16_t i = 0; i < 10; ++i) {
        CHECK(queue.push(packet_with_id(i)));
    }
    auto batch = queue.pop_batch(10, std::chrono::milliseconds(50));
    CHECK_EQ_SIZE(batch.size(), 10u);
    for (uint16_t i = 0; i < 10; ++i) {
        CHECK(batch[i].meta.src_port == i);
    }
}

void test_pop_batch_is_capped_by_max_n() {
    PacketQueue queue(100);
    for (uint16_t i = 0; i < 10; ++i) {
        queue.push(packet_with_id(i));
    }
    auto batch = queue.pop_batch(4, std::chrono::milliseconds(50));
    CHECK_EQ_SIZE(batch.size(), 4u);
    CHECK_EQ_SIZE(queue.size(), 6u);
}

void test_pop_batch_times_out_when_empty() {
    PacketQueue queue(10);
    const auto start = std::chrono::steady_clock::now();
    auto batch = queue.pop_batch(8, std::chrono::milliseconds(50));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK_EQ_SIZE(batch.size(), 0u);
    // It must actually block for roughly the timeout (this is what lets an
    // idle worker periodically re-check the shutdown flag), not spin.
    CHECK(elapsed >= std::chrono::milliseconds(40));
    CHECK(!queue.is_finished());  // no shutdown yet: just idle
}

void test_push_blocks_when_full_instead_of_dropping() {
    PacketQueue queue(4);
    for (uint16_t i = 0; i < 4; ++i) {
        CHECK(queue.push(packet_with_id(i)));
    }

    std::atomic<bool> push_returned{false};
    std::thread producer([&] {
        queue.push(packet_with_id(99));  // must block: queue is full
        push_returned.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK(!push_returned.load());  // still blocked => backpressure, not a drop

    auto batch = queue.pop_batch(1, std::chrono::milliseconds(50));
    CHECK_EQ_SIZE(batch.size(), 1u);
    producer.join();
    CHECK(push_returned.load());
    CHECK_EQ_SIZE(queue.size(), 4u);
}

void test_shutdown_unblocks_a_blocked_push() {
    PacketQueue queue(2);
    queue.push(packet_with_id(1));
    queue.push(packet_with_id(2));

    std::atomic<bool> finished{false};
    std::thread producer([&] {
        queue.push(packet_with_id(3));
        finished.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(!finished.load());
    queue.shutdown();
    producer.join();
    CHECK(finished.load());  // shutdown released it rather than hanging forever
}

void test_shutdown_drains_remaining_packets() {
    PacketQueue queue(100);
    for (uint16_t i = 0; i < 7; ++i) {
        queue.push(packet_with_id(i));
    }
    queue.shutdown();

    CHECK(!queue.is_finished());  // still holding packets
    auto batch = queue.pop_batch(100, std::chrono::milliseconds(10));
    CHECK_EQ_SIZE(batch.size(), 7u);  // queued work is delivered, not discarded
    CHECK(queue.is_finished());       // only now is it done
}

void test_no_packets_lost_across_many_producers_and_consumers() {
    constexpr size_t kPerProducer = 2000;
    constexpr size_t kProducers = 3;
    PacketQueue queue(16);  // deliberately tiny: forces constant backpressure

    std::atomic<size_t> consumed{0};
    std::vector<std::thread> consumers;
    for (int c = 0; c < 4; ++c) {
        consumers.emplace_back([&] {
            while (true) {
                auto batch = queue.pop_batch(8, std::chrono::milliseconds(20));
                consumed.fetch_add(batch.size());
                if (batch.empty() && queue.is_finished()) break;
            }
        });
    }

    std::vector<std::thread> producers;
    for (size_t p = 0; p < kProducers; ++p) {
        producers.emplace_back([&] {
            for (size_t i = 0; i < kPerProducer; ++i) {
                queue.push(packet_with_id(static_cast<uint16_t>(i)));
            }
        });
    }
    for (auto& t : producers) t.join();
    queue.shutdown();
    for (auto& t : consumers) t.join();

    CHECK_EQ_SIZE(consumed.load(), kPerProducer * kProducers);
}

void test_queued_packet_owns_its_payload() {
    // The parser hands out a pointer into pcap's transient buffer; the
    // queued copy must survive that buffer going away.
    ParsedPacket parsed;
    parsed.has_ip = true;
    QueuedPacket queued;
    {
        std::vector<uint8_t> scratch{1, 2, 3, 4, 5};
        parsed.payload = scratch.data();
        parsed.payload_length = scratch.size();
        queued = make_queued_packet(parsed);
    }  // scratch destroyed here

    CHECK_EQ_SIZE(queued.payload_size(), 5u);
    for (uint8_t i = 0; i < 5; ++i) {
        CHECK(queued.payload_data()[i] == i + 1);
    }
    CHECK(queued.meta.payload == nullptr);  // dangling pointer must be cleared
}

}  // namespace

int main() {
    test_batch_pop_preserves_fifo_order();
    test_pop_batch_is_capped_by_max_n();
    test_pop_batch_times_out_when_empty();
    test_push_blocks_when_full_instead_of_dropping();
    test_shutdown_unblocks_a_blocked_push();
    test_shutdown_drains_remaining_packets();
    test_no_packets_lost_across_many_producers_and_consumers();
    test_queued_packet_owns_its_payload();
    return report("queue");
}

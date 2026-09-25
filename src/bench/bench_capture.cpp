// Capture thread on its own: how fast one thread can read, decode, copy and
// queue packets from a capture file, with no analysis at all. Each stage adds
// one step to the one before, so the drop from one line to the next is what
// that step costs. If the last line is close to the end-to-end packets/sec,
// the capture thread is what limits the pipeline.
//
// Stages (cumulative):
//   read          pcap_next_ex only
//   + decode      parse_packet (Ethernet/IP/TCP/UDP headers)
//   + copy        payload memcpy'd into one reused buffer (the copy alone)
//   + allocate    make_queued_packet: the payload in its own heap allocation,
//                 as the real pipeline does (freed right away, same thread)
//   + queue       each packet pushed into a PacketQueue while worker threads
//                 drain it with pop_batch and throw the packets away (freed
//                 on the worker thread, as in the real pipeline)
//
// One extra line, outside the cumulative table, queues packets without their
// payload (no heap allocation, nothing freed on another thread). Comparing it
// with "+ queue" separates the cost of the queue itself (locking, waking
// workers) from the cost of allocating on one thread and freeing on another.
//
// Usage: bench_capture [-w workers] [-b batch] [-L linger_us] [-q capacity]
//                      [--reps N] capture.pcap
#include <pcap.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "netsentinel/packet_queue.hpp"
#include "netsentinel/parser.hpp"

namespace {

enum class Stage { kRead, kDecode, kCopy, kAllocate, kQueue, kQueueNoPayload };

struct Options {
    std::string path;
    size_t workers = 0;
    size_t batch = 256;
    long linger_us = 2000;
    size_t capacity = 4096;
    int reps = 5;
};

struct Result {
    size_t packets = 0;
    double seconds = 0;
    double avg_batch = 0;  // queue stage only
};

// Keeps the compiler from optimizing the measured work away.
std::atomic<uint64_t> g_sink{0};

pcap_t* open_or_die(const std::string& path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_offline(path.c_str(), errbuf);
    if (handle == nullptr) {
        std::fprintf(stderr, "cannot open %s: %s\n", path.c_str(), errbuf);
        std::exit(EXIT_FAILURE);
    }
    return handle;
}

Result run_stage(Stage stage, const Options& opt) {
    pcap_t* handle = open_or_die(opt.path);

    netsentinel::PacketQueue queue(opt.capacity);
    std::atomic<size_t> consumed{0};
    std::atomic<size_t> batches{0};
    std::vector<std::thread> workers;
    const bool queued_stage = stage == Stage::kQueue || stage == Stage::kQueueNoPayload;
    if (queued_stage) {
        for (size_t i = 0; i < opt.workers; ++i) {
            workers.emplace_back([&] {
                while (true) {
                    auto batch = queue.pop_batch(opt.batch, std::chrono::milliseconds(100),
                                                 std::chrono::microseconds(opt.linger_us));
                    if (!batch.empty()) {
                        consumed.fetch_add(batch.size(), std::memory_order_relaxed);
                        batches.fetch_add(1, std::memory_order_relaxed);
                    } else if (queue.is_finished()) {
                        return;
                    }
                }
            });
        }
    }

    std::vector<uint8_t> reused(65536);
    uint64_t sink = 0;
    size_t packets = 0;
    const auto start = std::chrono::steady_clock::now();

    struct pcap_pkthdr* header = nullptr;
    const uint8_t* data = nullptr;
    while (pcap_next_ex(handle, &header, &data) == 1) {
        if (stage == Stage::kRead) {
            sink += header->caplen;
            ++packets;
            continue;
        }
        auto parsed = netsentinel::parse_packet(data, header->caplen, header->len, header->ts);
        if (!parsed) continue;
        ++packets;
        switch (stage) {
            case Stage::kRead:
                break;
            case Stage::kDecode:
                sink += parsed->payload_length + parsed->dst_port;
                break;
            case Stage::kCopy:
                if (parsed->payload_length > 0) {
                    std::memcpy(reused.data(), parsed->payload,
                                std::min(parsed->payload_length, reused.size()));
                }
                sink += reused[0];
                break;
            case Stage::kAllocate: {
                auto queued = netsentinel::make_queued_packet(*parsed);
                sink += queued.payload_size();
                break;
            }
            case Stage::kQueue:
                queue.push(netsentinel::make_queued_packet(*parsed));
                break;
            case Stage::kQueueNoPayload: {
                netsentinel::QueuedPacket meta_only;
                meta_only.meta = *parsed;
                meta_only.meta.payload = nullptr;
                meta_only.meta.payload_length = 0;
                queue.push(std::move(meta_only));
                break;
            }
        }
    }

    Result result;
    result.packets = packets;
    if (queued_stage) {
        // The stage ends when the workers have taken every packet, not when
        // the last push returns, so a slow consumer side shows up here too.
        queue.shutdown();
        for (auto& t : workers) t.join();
        if (consumed.load() != packets) {
            std::fprintf(stderr, "queue lost packets: pushed %zu, consumed %zu\n", packets,
                         consumed.load());
            std::exit(EXIT_FAILURE);
        }
        const size_t b = batches.load();
        result.avg_batch = b > 0 ? static_cast<double>(packets) / static_cast<double>(b) : 0;
    }
    result.seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    pcap_close(handle);
    g_sink.fetch_add(sink, std::memory_order_relaxed);
    return result;
}

double median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    return n % 2 == 1 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

bool parse_count(const char* text, const char* flag, long max, long& out) {
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    if (end == text || *end != '\0' || value < 0 || value > max) {
        std::fprintf(stderr, "%s expects a number from 0 to %ld\n", flag, max);
        return false;
    }
    out = value;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    Options opt;
    const unsigned cores = std::thread::hardware_concurrency();
    opt.workers = cores > 1 ? cores - 1 : 1;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const bool has_value = i + 1 < argc;
        long value = 0;
        if (arg == "-w" && has_value) {
            if (!parse_count(argv[++i], "-w", 256, value) || value == 0) return EXIT_FAILURE;
            opt.workers = static_cast<size_t>(value);
        } else if (arg == "-b" && has_value) {
            if (!parse_count(argv[++i], "-b", 1 << 20, value) || value == 0) return EXIT_FAILURE;
            opt.batch = static_cast<size_t>(value);
        } else if (arg == "-L" && has_value) {
            if (!parse_count(argv[++i], "-L", 1000000, value)) return EXIT_FAILURE;
            opt.linger_us = value;
        } else if (arg == "-q" && has_value) {
            if (!parse_count(argv[++i], "-q", 1 << 24, value) || value == 0) return EXIT_FAILURE;
            opt.capacity = static_cast<size_t>(value);
        } else if (arg == "--reps" && has_value) {
            if (!parse_count(argv[++i], "--reps", 1000, value) || value == 0) return EXIT_FAILURE;
            opt.reps = static_cast<int>(value);
        } else if (!arg.empty() && arg[0] != '-' && opt.path.empty()) {
            opt.path = arg;
        } else {
            std::fprintf(stderr,
                         "usage: %s [-w workers] [-b batch] [-L linger_us] [-q capacity] "
                         "[--reps N] capture.pcap\n",
                         argv[0]);
            return EXIT_FAILURE;
        }
    }
    if (opt.path.empty()) {
        std::fprintf(stderr, "usage: %s [options] capture.pcap\n", argv[0]);
        return EXIT_FAILURE;
    }

    const struct {
        Stage stage;
        const char* name;
    } stages[] = {
        {Stage::kRead, "read"},
        {Stage::kDecode, "+ decode"},
        {Stage::kCopy, "+ copy (reused buffer)"},
        {Stage::kAllocate, "+ allocate (heap per packet)"},
        {Stage::kQueue, "+ queue (to workers)"},
        {Stage::kQueueNoPayload, "queue, payload not copied"},
    };
    constexpr size_t kStages = sizeof(stages) / sizeof(stages[0]);
    constexpr size_t kCumulative = kStages - 1;  // the last line is a comparison

    // One untimed pass pulls the file into the page cache.
    run_stage(Stage::kRead, opt);

    std::printf("capture thread alone: %s, %zu workers, batch %zu, linger %ld us, "
                "queue %zu, median of %d\n\n",
                opt.path.c_str(), opt.workers, opt.batch, opt.linger_us, opt.capacity, opt.reps);

    // Stages are interleaved within each repetition so slow drift (thermal
    // throttling, background load) hits all of them alike.
    std::vector<std::vector<double>> seconds(kStages);
    std::vector<double> avg_batches;
    size_t packets[kStages] = {};
    for (int rep = 0; rep < opt.reps; ++rep) {
        for (size_t s = 0; s < kStages; ++s) {
            const Result r = run_stage(stages[s].stage, opt);
            seconds[s].push_back(r.seconds);
            packets[s] = r.packets;
            if (stages[s].stage == Stage::kQueue) avg_batches.push_back(r.avg_batch);
        }
    }

    std::printf("%-30s %12s %14s %14s\n", "stage", "packets/sec", "ns/packet", "step costs");
    double previous_ns = 0;
    for (size_t s = 0; s < kStages; ++s) {
        const double sec = median(seconds[s]);
        const double pps = static_cast<double>(packets[s]) / sec;
        const double ns = 1e9 / pps;
        char step[32] = "";
        if (s > 0 && s < kCumulative) {
            std::snprintf(step, sizeof(step), "%+.0f ns", ns - previous_ns);
        }
        if (s == kCumulative) std::printf("\ncompare with \"+ queue\":\n");
        std::printf("%-30s %12.0f %14.0f %14s\n", stages[s].name, pps, ns, step);
        previous_ns = ns;
    }
    std::printf("\npackets: %zu read, %zu decoded; avg batch taken by workers: %.1f\n",
                packets[0], packets[kCumulative - 1], median(avg_batches));
    return g_sink.load() == 0xdeadbeef ? 1 : 0;  // never true; keeps g_sink alive
}

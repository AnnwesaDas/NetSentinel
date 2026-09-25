// Worker side on its own: how fast the detection rules process packets that
// are already in memory, with no capture thread and no queue. Complements
// bench_capture, which times everything before the workers.
//
// Part 1 times each rule on one thread, so their costs can be compared.
// Part 2 runs each rule on 1, 2, 4, ... threads at once. A rule whose
// throughput stops growing as threads are added is limited by something
// shared (a lock, memory bandwidth, slower cores), not by its own work.
//
// Rules (entropy on the CPU backend throughout):
//   entropy      Shannon entropy of every payload of 32+ bytes
//   signature    hash of every payload, looked up in the signature set
//   flow         port-scan and SYN-flood state (FlowTracker, 16 locked shards)
//   all          AnalysisEngine::analyze_batch, what a real worker runs
//
// Usage: bench_analysis [-b batch] [--reps N] [--max-threads N] capture.pcap
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "netsentinel/analysis_engine.hpp"
#include "netsentinel/capture.hpp"
#include "netsentinel/entropy_backend.hpp"
#include "netsentinel/flow_tracker.hpp"
#include "netsentinel/packet_queue.hpp"
#include "netsentinel/signature_db.hpp"

using netsentinel::QueuedPacket;

namespace {

enum class Rule { kEntropy, kSignature, kFlow, kAll };

constexpr struct {
    Rule rule;
    const char* name;
} kRules[] = {
    {Rule::kEntropy, "entropy"},
    {Rule::kSignature, "signature"},
    {Rule::kFlow, "flow"},
    {Rule::kAll, "all"},
};

constexpr size_t kEntropyMinPayload = 32;  // matches AnalysisConfig's default

// Keeps the compiler from optimizing the measured work away.
std::atomic<uint64_t> g_sink{0};

// Seconds for `threads` threads to process every packet once with `rule`.
// Threads take batches from a shared counter, like workers popping the queue.
// Stateful objects are rebuilt per run so every run starts from empty state.
double run_rule(Rule rule, std::vector<QueuedPacket>& packets, size_t batch_size,
                size_t threads) {
    netsentinel::CpuEntropyBackend entropy;
    netsentinel::SignatureDatabase signatures;
    netsentinel::FlowTracker flow;
    std::atomic<uint64_t> alerts{0};
    netsentinel::AnalysisEngine engine(
        [&](const netsentinel::Alert&) { alerts.fetch_add(1, std::memory_order_relaxed); });

    const size_t batch_count = (packets.size() + batch_size - 1) / batch_size;
    std::atomic<size_t> next_batch{0};

    auto work = [&] {
        std::vector<QueuedPacket> batch;
        std::vector<const QueuedPacket*> eligible;
        std::vector<double> entropies;
        uint64_t sink = 0;
        while (true) {
            const size_t b = next_batch.fetch_add(1, std::memory_order_relaxed);
            if (b >= batch_count) break;
            const size_t begin = b * batch_size;
            const size_t end = std::min(begin + batch_size, packets.size());
            switch (rule) {
                case Rule::kEntropy:
                    eligible.clear();
                    for (size_t i = begin; i < end; ++i) {
                        if (packets[i].payload_size() >= kEntropyMinPayload) {
                            eligible.push_back(&packets[i]);
                        }
                    }
                    if (!eligible.empty()) entropy.compute(eligible, entropies);
                    sink += entropies.size();
                    break;
                case Rule::kSignature:
                    for (size_t i = begin; i < end; ++i) {
                        sink += signatures.matches(packets[i].payload_data(),
                                                   packets[i].payload_size());
                    }
                    break;
                case Rule::kFlow:
                    for (size_t i = begin; i < end; ++i) {
                        sink += flow.observe(packets[i]).size();
                    }
                    break;
                case Rule::kAll:
                    // analyze_batch wants the packets in a vector of their
                    // own. Copying the payloads in would cost more than the
                    // rules, so each payload is swapped in and swapped back
                    // afterwards. Batches don't overlap, so no two threads
                    // touch the same packet.
                    batch.resize(end - begin);
                    for (size_t i = begin; i < end; ++i) {
                        batch[i - begin].meta = packets[i].meta;
                        batch[i - begin].payload.swap(packets[i].payload);
                    }
                    engine.analyze_batch(batch);
                    for (size_t i = begin; i < end; ++i) {
                        batch[i - begin].payload.swap(packets[i].payload);
                    }
                    break;
            }
        }
        g_sink.fetch_add(sink, std::memory_order_relaxed);
    };

    const auto start = std::chrono::steady_clock::now();
    std::vector<std::thread> pool;
    for (size_t t = 0; t < threads; ++t) pool.emplace_back(work);
    for (auto& t : pool) t.join();
    const double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    g_sink.fetch_add(alerts.load(), std::memory_order_relaxed);
    return seconds;
}

double median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    return n % 2 == 1 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

bool parse_count(const char* text, const char* flag, long max, long& out) {
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    if (end == text || *end != '\0' || value < 1 || value > max) {
        std::fprintf(stderr, "%s expects a number from 1 to %ld\n", flag, max);
        return false;
    }
    out = value;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::string path;
    size_t batch_size = 256;
    int reps = 5;
    const unsigned cores = std::thread::hardware_concurrency();
    size_t max_threads = cores > 0 ? cores : 4;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const bool has_value = i + 1 < argc;
        long value = 0;
        if (arg == "-b" && has_value) {
            if (!parse_count(argv[++i], "-b", 1 << 20, value)) return EXIT_FAILURE;
            batch_size = static_cast<size_t>(value);
        } else if (arg == "--reps" && has_value) {
            if (!parse_count(argv[++i], "--reps", 1000, value)) return EXIT_FAILURE;
            reps = static_cast<int>(value);
        } else if (arg == "--max-threads" && has_value) {
            if (!parse_count(argv[++i], "--max-threads", 256, value)) return EXIT_FAILURE;
            max_threads = static_cast<size_t>(value);
        } else if (!arg.empty() && arg[0] != '-' && path.empty()) {
            path = arg;
        } else {
            std::fprintf(stderr,
                         "usage: %s [-b batch] [--reps N] [--max-threads N] capture.pcap\n",
                         argv[0]);
            return EXIT_FAILURE;
        }
    }
    if (path.empty()) {
        std::fprintf(stderr, "usage: %s [options] capture.pcap\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Load every packet into memory first, so no capture work is timed.
    netsentinel::Capture capture;
    std::string error;
    if (!capture.open_offline(path, error)) {
        std::fprintf(stderr, "cannot open %s: %s\n", path.c_str(), error.c_str());
        return EXIT_FAILURE;
    }
    std::vector<QueuedPacket> packets;
    capture.run([&](const netsentinel::ParsedPacket& parsed) {
        packets.push_back(netsentinel::make_queued_packet(parsed));
    });
    if (packets.empty()) {
        std::fprintf(stderr, "%s has no packets this parser understands\n", path.c_str());
        return EXIT_FAILURE;
    }

    std::vector<size_t> thread_counts;
    for (size_t t = 1; t < max_threads; t *= 2) thread_counts.push_back(t);
    if (max_threads > 2) thread_counts.push_back(max_threads - 1);  // netsentinel's default
    thread_counts.push_back(max_threads);
    std::sort(thread_counts.begin(), thread_counts.end());
    thread_counts.erase(std::unique(thread_counts.begin(), thread_counts.end()),
                        thread_counts.end());

    std::printf("worker side alone: %s, %zu packets in memory, batch %zu, median of %d\n\n",
                path.c_str(), packets.size(), batch_size, reps);

    // Every (rule, thread count) pair is measured once per repetition, in
    // the same order, so slow drift (thermal throttling) hits all alike.
    constexpr size_t kRuleCount = sizeof(kRules) / sizeof(kRules[0]);
    std::vector<std::vector<std::vector<double>>> seconds(
        kRuleCount, std::vector<std::vector<double>>(thread_counts.size()));
    for (const auto& r : kRules) run_rule(r.rule, packets, batch_size, 1);  // warm-up
    for (int rep = 0; rep < reps; ++rep) {
        for (size_t r = 0; r < kRuleCount; ++r) {
            for (size_t t = 0; t < thread_counts.size(); ++t) {
                seconds[r][t].push_back(
                    run_rule(kRules[r].rule, packets, batch_size, thread_counts[t]));
            }
        }
    }

    const double n = static_cast<double>(packets.size());
    std::printf("one thread:\n%-12s %14s %12s\n", "rule", "packets/sec", "ns/packet");
    for (size_t r = 0; r < kRuleCount; ++r) {
        const double pps = n / median(seconds[r][0]);
        std::printf("%-12s %14.0f %12.0f\n", kRules[r].name, pps, 1e9 / pps);
    }

    std::printf("\nmillion packets/sec by thread count (x = speedup over one thread):\n%-12s",
                "rule");
    for (size_t t : thread_counts) std::printf(" %13zu", t);
    std::printf("\n");
    for (size_t r = 0; r < kRuleCount; ++r) {
        std::printf("%-12s", kRules[r].name);
        const double one = n / median(seconds[r][0]);
        for (size_t t = 0; t < thread_counts.size(); ++t) {
            const double pps = n / median(seconds[r][t]);
            char cell[32];
            std::snprintf(cell, sizeof(cell), "%.2f (%.1fx)", pps / 1e6, pps / one);
            std::printf(" %13s", cell);
        }
        std::printf("\n");
    }
    return g_sink.load() == 0xdeadbeef ? 1 : 0;  // never true; keeps g_sink alive
}

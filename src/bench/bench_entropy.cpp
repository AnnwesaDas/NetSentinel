// Entropy stage on its own: the CPU backend against the GPU backend on
// identical batches, across batch sizes and payload sizes. The end-to-end
// pipeline number mixes in capture, queueing and the other rules; this one
// isolates the work the GPU actually replaces.
//
// Usage: bench_entropy [--csv path]
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "netsentinel/entropy_backend.hpp"

#ifdef NETSENTINEL_HAS_METAL
#include "netsentinel/gpu/gpu_entropy_backend.hpp"
#endif

using netsentinel::CpuEntropyBackend;
using netsentinel::EntropyBackend;
using netsentinel::QueuedPacket;

namespace {

constexpr int kReps = 7;
constexpr size_t kMaxPackets = 65536;
// Caps the number of dispatches per run, so batch size 1 on the GPU (one
// dispatch per packet) finishes in reasonable time.
constexpr size_t kMaxBatchesPerRun = 512;

struct Row {
    std::string backend;
    size_t payload_bytes;
    size_t batch_size;
    double packets_per_sec;
    double megabytes_per_sec;
    double max_abs_error;  // vs the CPU backend on the same packets
};

std::vector<QueuedPacket> make_packets(size_t count, size_t payload_bytes) {
    std::mt19937 rng(99);
    std::vector<QueuedPacket> packets(count);
    for (auto& p : packets) {
        p.payload.resize(payload_bytes);
        for (auto& b : p.payload) b = static_cast<uint8_t>(rng());
    }
    return packets;
}

// Median seconds for one pass over `packets` in batches of `batch_size`.
// Also leaves the last pass's results in `results`.
double time_backend(EntropyBackend& backend, const std::vector<const QueuedPacket*>& packets,
                    size_t batch_size, std::vector<double>& results) {
    std::vector<const QueuedPacket*> batch;
    std::vector<double> out;
    auto one_pass = [&](bool keep) {
        for (size_t i = 0; i < packets.size(); i += batch_size) {
            batch.assign(packets.begin() + i,
                         packets.begin() + std::min(i + batch_size, packets.size()));
            if (!backend.compute(batch, out)) {
                std::fprintf(stderr, "%s backend failed\n", backend.name().c_str());
                std::exit(EXIT_FAILURE);
            }
            if (keep) results.insert(results.end(), out.begin(), out.end());
        }
    };

    one_pass(false);  // warm-up: first GPU dispatch pays one-time setup costs
    std::vector<double> seconds;
    for (int rep = 0; rep < kReps; ++rep) {
        const auto start = std::chrono::steady_clock::now();
        one_pass(false);
        seconds.push_back(
            std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());
    }
    results.clear();
    one_pass(true);
    std::sort(seconds.begin(), seconds.end());
    return seconds[seconds.size() / 2];
}

}  // namespace

int main(int argc, char** argv) {
    const char* csv_path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv_path = argv[++i];
        } else {
            std::fprintf(stderr, "usage: %s [--csv path]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    std::vector<std::unique_ptr<EntropyBackend>> backends;
    backends.push_back(std::make_unique<CpuEntropyBackend>());
#ifdef NETSENTINEL_HAS_METAL
    auto gpu = std::make_unique<netsentinel::gpu::GpuEntropyBackend>();
    if (!gpu->ok()) {
        std::fprintf(stderr, "GPU unavailable: %s\n", gpu->error().c_str());
        return EXIT_FAILURE;
    }
    backends.push_back(std::move(gpu));
#else
    std::printf("(no Metal in this build: CPU rows only)\n");
#endif

    std::vector<Row> rows;
    std::printf("%-22s %8s %6s %14s %10s %8s %10s\n", "backend", "payload", "batch",
                "packets/sec", "MB/s", "vs cpu", "max err");
    for (size_t payload : {64, 512, 1460}) {
        const auto all_packets = make_packets(kMaxPackets, payload);
        for (size_t batch : {1, 16, 64, 256, 1024, 4096}) {
            const size_t count = std::min(kMaxPackets, batch * kMaxBatchesPerRun);
            std::vector<const QueuedPacket*> packets;
            for (size_t i = 0; i < count; ++i) packets.push_back(&all_packets[i]);

            std::vector<double> cpu_results;
            double cpu_pps = 0.0;
            for (auto& backend : backends) {
                std::vector<double> results;
                const double seconds = time_backend(*backend, packets, batch, results);
                const bool is_cpu = backend->name() == "cpu";
                if (is_cpu) cpu_results = results;

                double max_error = 0.0;
                for (size_t i = 0; i < results.size() && i < cpu_results.size(); ++i) {
                    max_error = std::max(max_error, std::fabs(results[i] - cpu_results[i]));
                }
                const double pps = count / seconds;
                if (is_cpu) cpu_pps = pps;
                rows.push_back({backend->name(), payload, batch, pps, pps * payload / 1e6, max_error});
                std::printf("%-22s %8zu %6zu %14.0f %10.1f %7.2fx %10.2g\n", backend->name().c_str(),
                            payload, batch, pps, pps * payload / 1e6, cpu_pps > 0 ? pps / cpu_pps : 0.0,
                            max_error);
            }
        }
    }

    if (csv_path != nullptr) {
        FILE* f = std::fopen(csv_path, "w");
        if (f == nullptr) {
            std::perror(csv_path);
            return EXIT_FAILURE;
        }
        std::fprintf(f, "backend,payload_bytes,batch_size,packets_per_sec,megabytes_per_sec,max_abs_error\n");
        for (const auto& r : rows) {
            std::fprintf(f, "%s,%zu,%zu,%.0f,%.2f,%.3g\n", r.backend.c_str(), r.payload_bytes,
                         r.batch_size, r.packets_per_sec, r.megabytes_per_sec, r.max_abs_error);
        }
        std::fclose(f);
    }
    return EXIT_SUCCESS;
}

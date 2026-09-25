// Capture thread -> bounded queue -> worker pool. Each worker hands its
// batch to AnalysisEngine::analyze_batch (entropy, signature match, port
// scan, SYN flood) and alerts are printed as they fire. Entropy runs on the
// CPU by default, or on the Metal GPU with -g in Metal-enabled builds.
// Per-packet tracing is opt-in via -v.
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#include "netsentinel/alert.hpp"
#include "netsentinel/analysis_engine.hpp"
#include "netsentinel/capture.hpp"
#include "netsentinel/packet.hpp"
#include "netsentinel/packet_queue.hpp"
#include "netsentinel/worker_pool.hpp"

#ifdef NETSENTINEL_HAS_METAL
#include "netsentinel/gpu/gpu_entropy_backend.hpp"
#endif

namespace {

netsentinel::Capture* g_capture_for_signal = nullptr;
std::mutex g_stdout_mutex;
std::atomic<uint64_t> g_alert_count{0};

void handle_sigint(int) {
    if (g_capture_for_signal != nullptr) {
        g_capture_for_signal->request_stop();
    }
}

void print_packet(const netsentinel::QueuedPacket& q) {
    using netsentinel::ipv4_to_string;
    using netsentinel::mac_to_string;
    using netsentinel::tcp_flags_to_string;
    using netsentinel::transport_to_string;
    using netsentinel::Transport;

    const auto& pkt = q.meta;

    std::lock_guard<std::mutex> lock(g_stdout_mutex);
    std::printf("[%ld.%06ld] len=%u cap=%u  %s -> %s", static_cast<long>(pkt.timestamp.tv_sec),
                static_cast<long>(pkt.timestamp.tv_usec), pkt.wire_length, pkt.capture_length,
                mac_to_string(pkt.src_mac).c_str(), mac_to_string(pkt.dst_mac).c_str());

    if (!pkt.has_ip) {
        std::printf("  (non-IPv4)\n");
        return;
    }

    std::printf("  %s", ipv4_to_string(pkt.src_ip).c_str());
    if (pkt.transport == Transport::kTCP || pkt.transport == Transport::kUDP) {
        std::printf(":%u", pkt.src_port);
    }
    std::printf(" -> %s", ipv4_to_string(pkt.dst_ip).c_str());
    if (pkt.transport == Transport::kTCP || pkt.transport == Transport::kUDP) {
        std::printf(":%u", pkt.dst_port);
    }

    std::printf(" proto=%s ttl=%u", transport_to_string(pkt.transport).c_str(), pkt.ttl);
    if (pkt.transport == Transport::kTCP) {
        std::printf(" flags=%s", tcp_flags_to_string(pkt.tcp_flags).c_str());
    }
    std::printf(" payload=%zuB\n", q.payload_size());
}

void print_alert(const netsentinel::Alert& alert) {
    std::lock_guard<std::mutex> lock(g_stdout_mutex);
    std::printf("%s\n", netsentinel::format_alert(alert).c_str());
    g_alert_count.fetch_add(1, std::memory_order_relaxed);
}

// Parses a non-negative integer option value. Returns false (leaving
// `out` untouched) on anything that isn't a clean, in-range number —
// std::atoi would silently turn "-1" into a huge size_t and "abc" into 0.
bool parse_nonnegative(const char* text, const char* flag, long long max_value, long long& out) {
    errno = 0;
    char* end = nullptr;
    const long long value = std::strtoll(text, &end, 10);
    if (end == text || *end != '\0' || errno == ERANGE || value < 0 || value > max_value) {
        std::fprintf(stderr, "invalid value for %s: '%s' (expected 0..%lld)\n", flag, text,
                      max_value);
        return false;
    }
    out = value;
    return true;
}

void print_usage(const char* argv0) {
    std::fprintf(stderr,
                  "Usage: %s -i <device> | -r <file.pcap> [options]\n"
                  "  -i <device>   capture live from a network interface\n"
                  "  -r <file>     replay packets from a .pcap file\n"
                  "  -c <count>    stop after this many parsed packets (0 = unlimited)\n"
                  "  -l            list available capture devices and exit\n"
                  "  -w <n>        worker thread count (default: hardware concurrency)\n"
                  "  -q <n>        bounded queue capacity (default: 4096)\n"
                  "  -b <n>        max packets a worker pops per batch (default: 64)\n"
                  "  -v            print every packet, not just alerts\n"
                  "  -e <bits>     high-entropy alert threshold, bits/byte (default: 7.0)\n"
                  "  -g            compute entropy on the Metal GPU (Metal builds only)\n",
                  argv0);
}

}  // namespace

int main(int argc, char** argv) {
    std::string device;
    std::string pcap_file;
    int max_packets = 0;
    bool list_only = false;
    bool verbose = false;
    bool use_gpu = false;
    size_t num_workers = std::max(1u, std::thread::hardware_concurrency());
    size_t queue_capacity = 4096;
    size_t batch_size = 64;
    double entropy_threshold = 7.0;

    for (int i = 1; i < argc; ++i) {
        long long value = 0;
        if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            device = argv[++i];
        } else if (std::strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (std::strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            if (!parse_nonnegative(argv[++i], "-c", INT32_MAX, value)) return EXIT_FAILURE;
            max_packets = static_cast<int>(value);
        } else if (std::strcmp(argv[i], "-l") == 0) {
            list_only = true;
        } else if (std::strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            if (!parse_nonnegative(argv[++i], "-w", 1024, value)) return EXIT_FAILURE;
            num_workers = static_cast<size_t>(value);
        } else if (std::strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            if (!parse_nonnegative(argv[++i], "-q", 1 << 24, value)) return EXIT_FAILURE;
            queue_capacity = static_cast<size_t>(value);
        } else if (std::strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            if (!parse_nonnegative(argv[++i], "-b", 1 << 20, value)) return EXIT_FAILURE;
            batch_size = static_cast<size_t>(value);
        } else if (std::strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (std::strcmp(argv[i], "-g") == 0) {
            use_gpu = true;
        } else if (std::strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            char* end = nullptr;
            const char* text = argv[++i];
            entropy_threshold = std::strtod(text, &end);
            if (end == text || *end != '\0' || entropy_threshold < 0.0 ||
                entropy_threshold > 8.0) {
                std::fprintf(stderr, "invalid value for -e: '%s' (expected 0.0..8.0)\n", text);
                return EXIT_FAILURE;
            }
        } else {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (list_only) {
        std::string error;
        auto devices = netsentinel::list_devices(error);
        if (!error.empty() && devices.empty()) {
            std::fprintf(stderr, "error listing devices: %s\n", error.c_str());
            return EXIT_FAILURE;
        }
        for (const auto& name : devices) {
            std::printf("%s\n", name.c_str());
        }
        return EXIT_SUCCESS;
    }

    if (device.empty() == pcap_file.empty()) {  // neither or both given
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (queue_capacity == 0 || batch_size == 0) {
        std::fprintf(stderr, "queue capacity and batch size must be positive\n");
        return EXIT_FAILURE;
    }

    netsentinel::Capture capture;
    std::string error;
    bool opened = device.empty() ? capture.open_offline(pcap_file, error)
                                  : capture.open_live(device, error);
    if (!opened) {
        std::fprintf(stderr, "failed to open capture source: %s\n", error.c_str());
        if (!device.empty()) {
            std::fprintf(stderr,
                          "(on macOS this is often the /dev/bpf* permission issue — see "
                          "README.md)\n");
        }
        return EXIT_FAILURE;
    }

    g_capture_for_signal = &capture;
    std::signal(SIGINT, handle_sigint);

    std::unique_ptr<netsentinel::EntropyBackend> backend;
    if (use_gpu) {
#ifdef NETSENTINEL_HAS_METAL
        auto gpu = std::make_unique<netsentinel::gpu::GpuEntropyBackend>();
        if (!gpu->ok()) {
            std::fprintf(stderr, "GPU unavailable: %s\n", gpu->error().c_str());
            return EXIT_FAILURE;
        }
        backend = std::move(gpu);
#else
        std::fprintf(stderr,
                      "-g needs a Metal build: cmake -S . -B build -DNETSENTINEL_ENABLE_METAL=ON\n");
        return EXIT_FAILURE;
#endif
    }

    netsentinel::AnalysisConfig analysis_config;
    analysis_config.entropy_threshold = entropy_threshold;
    netsentinel::AnalysisEngine engine(print_alert, analysis_config, std::move(backend));

    netsentinel::PacketQueue queue(queue_capacity);
    netsentinel::WorkerPool pool(
        num_workers, queue,
        [&](const std::vector<netsentinel::QueuedPacket>& batch) {
            if (verbose) {
                for (const auto& pkt : batch) {
                    print_packet(pkt);
                }
            }
            engine.analyze_batch(batch);
        },
        batch_size);

    std::printf("capturing from %s ... (%zu worker(s), queue capacity %zu, batch size %zu, "
                "entropy on %s)\n",
                device.empty() ? pcap_file.c_str() : device.c_str(), num_workers, queue_capacity,
                batch_size, engine.backend_name().c_str());

    const auto started = std::chrono::steady_clock::now();
    pool.start();

    int delivered = 0;
    {
        std::thread capture_thread([&] {
            delivered = capture.run(
                [&](const netsentinel::ParsedPacket& parsed) {
                    queue.push(netsentinel::make_queued_packet(parsed));
                },
                max_packets);
        });
        capture_thread.join();
    }

    queue.shutdown();
    pool.join();
    const double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

    const uint64_t processed = pool.processed_count();
    std::printf("done — %d packet(s) captured, %llu processed, %llu alert(s), %.3fs, "
                "%.0f packets/sec\n",
                delivered, static_cast<unsigned long long>(processed),
                static_cast<unsigned long long>(g_alert_count.load()), seconds,
                seconds > 0 ? processed / seconds : 0.0);
    if (engine.backend_fallbacks() > 0) {
        std::printf("warning: %llu batch(es) fell back to CPU entropy after a %s failure\n",
                    static_cast<unsigned long long>(engine.backend_fallbacks()),
                    engine.backend_name().c_str());
    }

    return EXIT_SUCCESS;
}

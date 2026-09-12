// Phase 2: capture thread -> bounded thread-safe queue -> worker thread
// pool consuming batches. Analysis is still just printing (Phase 3 swaps
// this callback for real anomaly rules); this phase is about the
// concurrency plumbing around it.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <functional>
#include <mutex>
#include <thread>

#include "netsentinel/capture.hpp"
#include "netsentinel/packet.hpp"
#include "netsentinel/packet_queue.hpp"
#include "netsentinel/worker_pool.hpp"

namespace {

netsentinel::Capture* g_capture_for_signal = nullptr;
std::mutex g_stdout_mutex;

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
    std::printf("[tid=%zx] [%ld.%06ld] len=%u cap=%u  %s -> %s",
                std::hash<std::thread::id>{}(std::this_thread::get_id()),
                static_cast<long>(pkt.timestamp.tv_sec), static_cast<long>(pkt.timestamp.tv_usec),
                pkt.wire_length, pkt.capture_length, mac_to_string(pkt.src_mac).c_str(),
                mac_to_string(pkt.dst_mac).c_str());

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

void print_usage(const char* argv0) {
    std::fprintf(stderr,
                  "Usage: %s -i <device> | -r <file.pcap> [options]\n"
                  "  -i <device>   capture live from a network interface\n"
                  "  -r <file>     replay packets from a .pcap file\n"
                  "  -c <count>    stop after this many parsed packets (0 = unlimited)\n"
                  "  -l            list available capture devices and exit\n"
                  "  -w <n>        worker thread count (default: hardware concurrency)\n"
                  "  -q <n>        bounded queue capacity (default: 4096)\n"
                  "  -b <n>        max packets a worker pops per batch (default: 64)\n",
                  argv0);
}

}  // namespace

int main(int argc, char** argv) {
    std::string device;
    std::string pcap_file;
    int max_packets = 0;
    bool list_only = false;
    size_t num_workers = std::max(1u, std::thread::hardware_concurrency());
    size_t queue_capacity = 4096;
    size_t batch_size = 64;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            device = argv[++i];
        } else if (std::strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (std::strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            max_packets = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "-l") == 0) {
            list_only = true;
        } else if (std::strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            num_workers = static_cast<size_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            queue_capacity = static_cast<size_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            batch_size = static_cast<size_t>(std::atoi(argv[++i]));
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

    netsentinel::PacketQueue queue(queue_capacity);
    netsentinel::WorkerPool pool(num_workers, queue, print_packet, batch_size);
    pool.start();

    std::printf("capturing from %s ... (%zu worker(s), queue capacity %zu, batch size %zu)\n",
                device.empty() ? pcap_file.c_str() : device.c_str(), num_workers, queue_capacity,
                batch_size);

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

    std::printf("done — %d packet(s) captured, %llu processed\n", delivered,
                static_cast<unsigned long long>(pool.processed_count()));

    return EXIT_SUCCESS;
}

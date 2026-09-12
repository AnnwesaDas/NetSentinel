#include "netsentinel/capture.hpp"

#include <pcap.h>
#include <poll.h>

#include <atomic>
#include <cerrno>
#include <cstring>

#include "netsentinel/parser.hpp"

namespace netsentinel {

namespace {
// pcap_breakloop() isn't usable with pcap_next_ex()'s polling loop below,
// so a plain atomic flag checked each iteration does the job instead.
std::atomic<bool> g_stop_requested{false};

constexpr int kPollTimeoutMs = 100;
}  // namespace

Capture::~Capture() {
    if (handle_ != nullptr) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool Capture::open_live(const std::string& device, std::string& error, int snaplen,
                         bool promiscuous, int timeout_ms) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_live(device.c_str(), snaplen, promiscuous ? 1 : 0, timeout_ms, errbuf);
    if (handle_ == nullptr) {
        error = errbuf;
        return false;
    }

    if (pcap_datalink(handle_) != DLT_EN10MB) {
        error = "unsupported link-layer type on " + device +
                " (only Ethernet/DLT_EN10MB is parsed in Phase 1)";
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }

    return true;
}

bool Capture::open_offline(const std::string& path, std::string& error) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_offline(path.c_str(), errbuf);
    if (handle_ == nullptr) {
        error = errbuf;
        return false;
    }

    if (pcap_datalink(handle_) != DLT_EN10MB) {
        error = path + " uses an unsupported link-layer type (only Ethernet/DLT_EN10MB is "
                        "parsed in Phase 1)";
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }

    return true;
}

int Capture::run(const PacketHandler& handler, int max_packets) {
    if (handle_ == nullptr) {
        return 0;
    }

    g_stop_requested.store(false, std::memory_order_relaxed);
    int delivered = 0;

    // On Linux, libpcap's own read-timeout (passed to pcap_open_live) is
    // driven by the TPACKET_V3 ring buffer's block-retire timer, which only
    // starts once at least one packet has actually arrived. With zero
    // traffic, pcap_next_ex() ends up calling poll() with an infinite
    // timeout and never returns — which would make request_stop() (e.g.
    // from SIGINT) hang forever. To get a real, bounded wakeup cadence we
    // poll the capture fd ourselves and only call pcap_next_ex() once it's
    // readable. This is a no-op for offline replay, where
    // pcap_get_selectable_fd() returns -1 and pcap_next_ex() already
    // returns immediately (a packet, or -2 at EOF).
    const int selectable_fd = pcap_get_selectable_fd(handle_);
    if (selectable_fd >= 0) {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_setnonblock(handle_, 1, errbuf);
    }

    while (!g_stop_requested.load(std::memory_order_relaxed)) {
        if (selectable_fd >= 0) {
            struct pollfd pfd {};
            pfd.fd = selectable_fd;
            pfd.events = POLLIN;
            const int poll_rc = ::poll(&pfd, 1, kPollTimeoutMs);
            if (poll_rc == 0) {
                continue;  // no data within our own timeout — recheck stop flag
            }
            if (poll_rc < 0) {
                if (errno == EINTR) {
                    continue;  // interrupted by a signal (e.g. SIGINT) — recheck stop flag
                }
                break;  // real poll error
            }
        }

        struct pcap_pkthdr* header = nullptr;
        const uint8_t* data = nullptr;
        const int rc = pcap_next_ex(handle_, &header, &data);

        if (rc == 1) {
            auto parsed = parse_packet(data, header->caplen, header->len, header->ts);
            if (parsed.has_value()) {
                handler(*parsed);
                ++delivered;
            }
            if (max_packets > 0 && delivered >= max_packets) {
                break;
            }
        } else if (rc == 0) {
            continue;  // nonblocking live read raced the poll and found nothing yet
        } else {
            break;  // rc == -1 (error) or rc == -2 (offline EOF)
        }
    }

    return delivered;
}

void Capture::request_stop() { g_stop_requested.store(true, std::memory_order_relaxed); }

std::vector<std::string> list_devices(std::string& error) {
    std::vector<std::string> names;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* devices = nullptr;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        error = errbuf;
        return names;
    }

    for (pcap_if_t* dev = devices; dev != nullptr; dev = dev->next) {
        names.emplace_back(dev->name);
    }

    pcap_freealldevs(devices);
    return names;
}

}  // namespace netsentinel

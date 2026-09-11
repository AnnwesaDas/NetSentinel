// Phase 0 smoke test: confirms libpcap is linked correctly and can enumerate
// capture devices. Real capture/parsing logic lands in Phase 1.
#include <pcap.h>

#include <cstdio>
#include <cstdlib>

int main() {
    std::printf("netsentinel — libpcap %s\n", pcap_lib_version());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices = nullptr;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    std::printf("Available capture devices:\n");
    int count = 0;
    for (pcap_if_t* dev = devices; dev != nullptr; dev = dev->next) {
        std::printf("  - %s%s%s\n", dev->name,
                    dev->description ? " : " : "",
                    dev->description ? dev->description : "");
        ++count;
    }

    if (count == 0) {
        std::printf(
            "  (none found — on macOS this usually means the process needs\n"
            "   permission to read /dev/bpf*; see README for the fix)\n");
    }

    pcap_freealldevs(devices);
    return EXIT_SUCCESS;
}

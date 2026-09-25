// Detection-rule tests. These pin down both directions: the rule fires on
// attack traffic, and stays quiet on traffic that merely resembles it.
#include "netsentinel/flow_tracker.hpp"

#include "test_support.hpp"

using namespace netsentinel;
using namespace nstest;

namespace {

size_t count_of(const std::vector<Alert>& alerts, AnomalyType type) {
    size_t n = 0;
    for (const auto& a : alerts) {
        if (a.type == type) ++n;
    }
    return n;
}

void test_port_scan_fires_at_threshold() {
    FlowTrackerConfig cfg;
    cfg.port_scan_distinct_port_threshold = 10;
    cfg.port_scan_window_ms = 5000;
    FlowTracker tracker(cfg);

    size_t port_scan_alerts = 0;
    for (int i = 0; i < 9; ++i) {
        auto pkt = make_test_packet("10.0.0.66", "10.0.0.1", 40000,
                                     static_cast<uint16_t>(1000 + i), kTcpFlagSyn, 1000 + i * 10);
        port_scan_alerts += count_of(tracker.observe(pkt), AnomalyType::kPortScan);
    }
    CHECK_EQ_SIZE(port_scan_alerts, 0u);  // 9 distinct ports: below threshold

    auto tenth = make_test_packet("10.0.0.66", "10.0.0.1", 40000, 1009, kTcpFlagSyn, 1100);
    port_scan_alerts += count_of(tracker.observe(tenth), AnomalyType::kPortScan);
    CHECK_EQ_SIZE(port_scan_alerts, 1u);  // 10th distinct port trips it
}

void test_repeated_same_port_is_not_a_scan() {
    // 100 packets to a single port is heavy traffic, not a port scan.
    FlowTrackerConfig cfg;
    cfg.port_scan_distinct_port_threshold = 10;
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 100; ++i) {
        auto pkt = make_test_packet("10.0.0.20", "10.0.0.1", 40000, 443, kTcpFlagAck, 1000 + i);
        alerts += count_of(tracker.observe(pkt), AnomalyType::kPortScan);
    }
    CHECK_EQ_SIZE(alerts, 0u);
}

void test_ports_outside_window_do_not_accumulate() {
    // Same 20 ports, but spread far enough apart that no 5s window ever
    // holds 10 of them.
    FlowTrackerConfig cfg;
    cfg.port_scan_distinct_port_threshold = 10;
    cfg.port_scan_window_ms = 5000;
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 20; ++i) {
        auto pkt = make_test_packet("10.0.0.21", "10.0.0.1", 40000,
                                     static_cast<uint16_t>(2000 + i), kTcpFlagSyn,
                                     static_cast<int64_t>(i) * 60000);  // one per minute
        alerts += count_of(tracker.observe(pkt), AnomalyType::kPortScan);
    }
    CHECK_EQ_SIZE(alerts, 0u);
}

void test_syn_flood_fires() {
    FlowTrackerConfig cfg;
    cfg.syn_flood_pending_threshold = 20;
    cfg.syn_flood_window_ms = 2000;
    cfg.port_scan_distinct_port_threshold = 1000;  // isolate the SYN-flood rule
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 25; ++i) {
        auto pkt = make_test_packet("10.0.0.99", "10.0.0.1",
                                     static_cast<uint16_t>(30000 + i), 80, kTcpFlagSyn,
                                     1000 + i * 10);
        alerts += count_of(tracker.observe(pkt), AnomalyType::kSynFlood);
    }
    CHECK(alerts >= 1u);
}

void test_completed_handshakes_do_not_look_like_a_flood() {
    // A busy but legitimate client: every SYN is followed by its own ACK
    // on the same 4-tuple, so nothing should stay pending.
    FlowTrackerConfig cfg;
    cfg.syn_flood_pending_threshold = 20;
    cfg.port_scan_distinct_port_threshold = 1000;
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 60; ++i) {
        const uint16_t sport = static_cast<uint16_t>(30000 + i);
        auto syn = make_test_packet("10.0.0.30", "10.0.0.1", sport, 80, kTcpFlagSyn, 1000 + i * 5);
        alerts += count_of(tracker.observe(syn), AnomalyType::kSynFlood);
        auto ack = make_test_packet("10.0.0.30", "10.0.0.1", sport, 80, kTcpFlagAck,
                                     1002 + i * 5);
        alerts += count_of(tracker.observe(ack), AnomalyType::kSynFlood);
    }
    CHECK_EQ_SIZE(alerts, 0u);
}

void test_stale_syns_expire_from_the_window() {
    FlowTrackerConfig cfg;
    cfg.syn_flood_pending_threshold = 20;
    cfg.syn_flood_window_ms = 2000;
    cfg.port_scan_distinct_port_threshold = 1000;
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 30; ++i) {
        // One SYN every 10 seconds — never 20 inside a 2s window.
        auto pkt = make_test_packet("10.0.0.31", "10.0.0.1",
                                     static_cast<uint16_t>(30000 + i), 80, kTcpFlagSyn,
                                     static_cast<int64_t>(i) * 10000);
        alerts += count_of(tracker.observe(pkt), AnomalyType::kSynFlood);
    }
    CHECK_EQ_SIZE(alerts, 0u);
}

void test_alerts_are_debounced() {
    FlowTrackerConfig cfg;
    cfg.port_scan_distinct_port_threshold = 5;
    cfg.port_scan_window_ms = 60000;
    cfg.alert_debounce_ms = 10000;
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 50; ++i) {
        auto pkt = make_test_packet("10.0.0.40", "10.0.0.1", 40000,
                                     static_cast<uint16_t>(3000 + i), kTcpFlagSyn, 1000 + i * 10);
        alerts += count_of(tracker.observe(pkt), AnomalyType::kPortScan);
    }
    // Without debouncing this would alert on all 46 packets past the
    // threshold; the whole run spans well under one debounce interval.
    CHECK_EQ_SIZE(alerts, 1u);
}

void test_sources_are_tracked_independently() {
    FlowTrackerConfig cfg;
    cfg.port_scan_distinct_port_threshold = 10;
    FlowTracker tracker(cfg);

    // Two IPs each touch 6 ports: neither alone crosses the threshold, and
    // their counts must not be pooled together.
    size_t alerts = 0;
    for (int i = 0; i < 6; ++i) {
        auto a = make_test_packet("10.0.0.51", "10.0.0.1", 40000,
                                   static_cast<uint16_t>(4000 + i), kTcpFlagSyn, 1000 + i);
        auto b = make_test_packet("10.0.0.52", "10.0.0.1", 40000,
                                   static_cast<uint16_t>(5000 + i), kTcpFlagSyn, 1000 + i);
        alerts += count_of(tracker.observe(a), AnomalyType::kPortScan);
        alerts += count_of(tracker.observe(b), AnomalyType::kPortScan);
    }
    CHECK_EQ_SIZE(alerts, 0u);
}

void test_busy_server_replies_are_not_a_scan() {
    // A web server answering 200 clients sends to 200 different ephemeral
    // ports. Replies (ACK, PSH-ACK) and handshake answers (SYN-ACK) are not
    // connection attempts, so none of this may count as scanning.
    FlowTrackerConfig cfg;
    cfg.port_scan_distinct_port_threshold = 10;
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 200; ++i) {
        const uint16_t client_port = static_cast<uint16_t>(40000 + i);
        const uint8_t flags = (i % 3 == 0)   ? (kTcpFlagSyn | kTcpFlagAck)
                              : (i % 3 == 1) ? kTcpFlagAck
                                             : (kTcpFlagPsh | kTcpFlagAck);
        auto reply = make_test_packet("172.16.0.1", "10.1.0.5", 443, client_port, flags, 1000 + i);
        alerts += count_of(tracker.observe(reply), AnomalyType::kPortScan);
    }
    CHECK_EQ_SIZE(alerts, 0u);
}

void test_dns_server_replies_are_not_a_scan() {
    FlowTrackerConfig cfg;
    cfg.port_scan_distinct_port_threshold = 10;
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 200; ++i) {
        auto reply = make_test_packet("8.8.8.8", "10.1.0.5", 53, static_cast<uint16_t>(50000 + i),
                                      0, 1000 + i, Transport::kUDP);
        alerts += count_of(tracker.observe(reply), AnomalyType::kPortScan);
    }
    CHECK_EQ_SIZE(alerts, 0u);
}

void test_udp_scan_is_still_detected() {
    // UDP probes from an ephemeral port to many destination ports.
    FlowTrackerConfig cfg;
    cfg.port_scan_distinct_port_threshold = 10;
    FlowTracker tracker(cfg);

    size_t alerts = 0;
    for (int i = 0; i < 20; ++i) {
        auto probe = make_test_packet("10.66.0.9", "10.0.0.1", 51000, static_cast<uint16_t>(100 + i),
                                      0, 1000 + i * 10, Transport::kUDP);
        alerts += count_of(tracker.observe(probe), AnomalyType::kPortScan);
    }
    CHECK_EQ_SIZE(alerts, 1u);
}

void test_non_ip_packets_are_ignored() {
    FlowTracker tracker;
    QueuedPacket pkt;  // has_ip defaults to false
    CHECK_EQ_SIZE(tracker.observe(pkt).size(), 0u);
}

void test_state_is_bounded_under_unique_source_flood() {
    // The classic spoofed-source flood: every packet from a different IP.
    // Tracked state must stay bounded rather than growing with the flood.
    FlowTrackerConfig cfg;
    cfg.num_shards = 4;
    cfg.max_tracked_ips_per_shard = 64;
    cfg.sweep_interval_packets = 128;
    cfg.idle_ttl_ms = 1000;
    FlowTracker tracker(cfg);

    for (int i = 0; i < 50000; ++i) {
        char ip[32];
        std::snprintf(ip, sizeof(ip), "%d.%d.%d.%d", 10 + (i >> 24) % 200, (i >> 16) & 0xff,
                      (i >> 8) & 0xff, i & 0xff);
        auto pkt = make_test_packet(ip, "10.0.0.1", 1234, 80, kTcpFlagSyn, 1000 + i);
        tracker.observe(pkt);
    }

    const size_t tracked = tracker.tracked_ip_count();
    // 50k unique sources seen; retained state must stay near the cap
    // (4 shards * 64 cap, plus at most one sweep interval of slack each).
    CHECK(tracked <= cfg.num_shards * (cfg.max_tracked_ips_per_shard +
                                        cfg.sweep_interval_packets));
    CHECK(tracked < 5000u);
}

void test_idle_sources_are_forgotten() {
    FlowTrackerConfig cfg;
    cfg.num_shards = 1;
    cfg.sweep_interval_packets = 1;  // sweep on every packet
    cfg.idle_ttl_ms = 5000;
    FlowTracker tracker(cfg);

    for (int i = 0; i < 10; ++i) {
        char ip[32];
        std::snprintf(ip, sizeof(ip), "10.7.0.%d", i + 1);
        auto pkt = make_test_packet(ip, "10.0.0.1", 1234, 80, kTcpFlagSyn, 1000);
        tracker.observe(pkt);
    }
    CHECK_EQ_SIZE(tracker.tracked_ip_count(), 10u);

    // A single much-later packet should retire all the now-idle records.
    auto later = make_test_packet("10.7.0.200", "10.0.0.1", 1234, 80, kTcpFlagSyn, 100000);
    tracker.observe(later);
    CHECK_EQ_SIZE(tracker.tracked_ip_count(), 1u);
}

}  // namespace

int main() {
    test_port_scan_fires_at_threshold();
    test_repeated_same_port_is_not_a_scan();
    test_ports_outside_window_do_not_accumulate();
    test_syn_flood_fires();
    test_completed_handshakes_do_not_look_like_a_flood();
    test_stale_syns_expire_from_the_window();
    test_alerts_are_debounced();
    test_sources_are_tracked_independently();
    test_busy_server_replies_are_not_a_scan();
    test_dns_server_replies_are_not_a_scan();
    test_udp_scan_is_still_detected();
    test_non_ip_packets_are_ignored();
    test_state_is_bounded_under_unique_source_flood();
    test_idle_sources_are_forgotten();
    return report("flow_tracker");
}

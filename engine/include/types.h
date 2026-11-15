#ifndef NETSIGHT_TYPES_H
#define NETSIGHT_TYPES_H

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace DPI {

// ============================================================================
// Hash helpers
// ============================================================================
inline uint64_t hashMix(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

inline uint64_t hashSeed() {
    static const uint64_t seed = [] {
        std::random_device rd;
        return (static_cast<uint64_t>(rd()) << 32) ^ static_cast<uint64_t>(rd());
    }();
    return seed;
}

// ============================================================================
// IP Address (IPv4 or IPv6)
// ============================================================================
// IPv4 keeps its four wire-order octets in bytes[0..3] (the rest zero).
// IPv6 uses all 16 bytes. Wire order ensures platform-endian independence.
struct IPAddress {
    std::array<uint8_t, 16> bytes{};
    uint8_t family = 4; // 4 or 6

    static IPAddress fromV4(const uint8_t* p) {
        IPAddress a;
        a.family = 4;
        std::memcpy(a.bytes.data(), p, 4);
        return a;
    }

    static IPAddress fromV6(const uint8_t* p) {
        IPAddress a;
        a.family = 6;
        std::memcpy(a.bytes.data(), p, 16);
        return a;
    }

    static IPAddress parse(const std::string& str);

    bool isV6() const { return family == 6; }
    bool operator==(const IPAddress& o) const { return family == o.family && bytes == o.bytes; }
    bool operator!=(const IPAddress& o) const { return !(*this == o); }
    bool operator<(const IPAddress& o) const {
        if (family != o.family) return family < o.family;
        return bytes < o.bytes;
    }

    std::string toString() const;
};

struct IPAddressHash {
    size_t operator()(const IPAddress& a) const {
        uint64_t lo, hi;
        std::memcpy(&lo, a.bytes.data(), 8);
        std::memcpy(&hi, a.bytes.data() + 8, 8);
        uint64_t h = hashMix(hashSeed() ^ lo);
        h = hashMix(h ^ hi);
        return static_cast<size_t>(h ^ a.family);
    }
};

// ============================================================================
// Five-Tuple: Uniquely identifies a bidirectional connection
// ============================================================================
struct FiveTuple {
    IPAddress src_ip;
    IPAddress dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0; // TCP=6, UDP=17, ICMP=1, ICMPv6=58

    bool operator==(const FiveTuple& other) const {
        return src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol &&
               src_ip == other.src_ip &&
               dst_ip == other.dst_ip;
    }

    // Bidirectional reverse tuple
    FiveTuple reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }

    // Canonical bidirectional tuple
    FiveTuple canonical() const {
        if (dst_ip < src_ip || (src_ip == dst_ip && dst_port < src_port)) {
            return reverse();
        }
        return *this;
    }

    std::string toString() const;
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        IPAddressHash ih;
        uint64_t h = hashMix(hashSeed() ^ ih(t.src_ip));
        h = hashMix(h ^ (ih(t.dst_ip) + 0x9e3779b97f4a7c15ULL));
        h = hashMix(h ^ ((static_cast<uint64_t>(t.src_port) << 24) |
                         (static_cast<uint64_t>(t.dst_port) << 8) | t.protocol));
        return static_cast<size_t>(h);
    }
};

// ============================================================================
// Application Classification
// ============================================================================
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    APP_COUNT
};

std::string appTypeToString(AppType type);
AppType stringToAppType(const std::string& str);
AppType sniToAppType(const std::string& sni);

// ============================================================================
// Connection State & Action
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    ALERTED,
    CLOSED
};

enum class PacketAction {
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
};

// ============================================================================
// Flow / Connection Record
// ============================================================================
struct Connection {
    FiveTuple tuple;              // initial outbound tuple direction (initiator -> responder)
    uint32_t generation = 0;      // flow instance / replay epoch counter
    ConnectionState state = ConnectionState::NEW;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;              // TLS Server Name Indication or HTTP Host
    std::string ja3_fingerprint;  // TLS Client Hello JA3 string
    std::vector<std::string> dns_queries;

    // Traffic volume and directional counters
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;

    // Packet-based timestamps (microseconds since Unix epoch)
    uint64_t first_seen_us = 0;
    uint64_t last_seen_us = 0;
    uint64_t last_export_us = 0;

    PacketAction action = PacketAction::FORWARD;

    // TCP flag counters
    uint32_t syn_count = 0;
    uint32_t syn_ack_count = 0;
    uint32_t fin_count = 0;
    uint32_t rst_count = 0;
    bool syn_seen = false;
    bool syn_ack_seen = false;
    bool fin_seen = false;
    bool rst_seen = false;
    uint8_t  last_tcp_flags = 0;

    // First 15 packet sizes and inter-packet arrival gaps
    std::vector<int> packet_sizes;
    std::vector<uint32_t> inter_packet_times_ms;

    // DNS diagnostics
    double dns_query_entropy = 0.0;
    size_t dns_query_length = 0;
    uint16_t dns_record_type = 0;
    uint32_t dns_query_count = 0;

    // Rule match (alert) tracking
    bool rule_match = false;
    std::string rule_reason;
    uint32_t checked_rules_version = 0;
    bool rule_checked = false;

    // TLS reassembly buffer for fragmented ClientHello
    std::vector<uint8_t> tls_buf;
    bool tls_done = false;
    uint32_t tls_next_seq = 0;
    bool dirty = true; // Changed since last export
};

} // namespace DPI

#endif // NETSIGHT_TYPES_H

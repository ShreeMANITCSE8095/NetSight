#ifndef HOST_PROFILER_H
#define HOST_PROFILER_H

#include "types.h"
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace DPI {

// Source-side behaviour of a host (port scans, fan-out, new-flow rate).
struct HostSummary {
    size_t distinct_dst_ips = 0;
    size_t distinct_dst_ports = 0;
    double mean_inter_arrival_ms = 0.0;
    double var_inter_arrival_ms = 0.0;   // sample variance
    size_t connection_count = 0;
};

// Destination-side ("victim") behaviour over a tumbling packet-time window.
// A spoofed-source flood or a reflection attack is invisible per flow: every
// flow looks like one lonely packet. It only shows up when you look at what
// arrives AT one address: many distinct sources, high source entropy, high rate.
// Reported values are those of the busiest recent window, so a flow exported
// late (idle expiry, end of capture) still sees the attack that hit its victim.
struct VictimSummary {
    size_t distinct_srcs = 0;
    double src_entropy_bits = 0.0;       // Shannon entropy of the source-IP distribution (per new flow)
    double flows_per_s = 0.0;
    double pkts_per_s = 0.0;
    double bytes_per_s = 0.0;
};

// History of flow START times for one (src, dst, dst_port, protocol). A beacon
// usually opens a fresh connection every interval, so periodicity lives
// between flows, not inside one.
struct PairSummary {
    size_t flow_count = 0;
    double interval_mean_ms = 0.0;
    double interval_std_ms = 0.0;
    double interval_cv = 0.0;            // std / mean: near 0 means very regular
};

class HostProfiler {
public:
    static HostProfiler& getInstance() {
        static HostProfiler instance;
        return instance;
    }

    // Record a NEW flow (first packet). Updates the source host profile, the
    // destination (victim) profile and the pair history. ts_us is packet time.
    void recordNewConnection(const IPAddress& src, const IPAddress& dst, uint16_t dst_port,
                             uint8_t protocol, uint64_t ts_us);

    // Count one packet (any direction) towards its destination address. Only
    // touches destinations that already have a profile, so it cannot be used
    // to grow the table.
    void recordPacket(const IPAddress& dst, uint32_t frame_bytes, uint64_t ts_us);

    // Cheap, O(1) lookups. Unknown key -> all zeros.
    HostSummary getStats(const IPAddress& src);
    VictimSummary getVictim(const IPAddress& dst);
    PairSummary getPair(const IPAddress& src, const IPAddress& dst, uint16_t dst_port, uint8_t protocol);

    // Drop entries not seen for idle_us. Returns how many were removed.
    size_t expireIdle(uint64_t now_us, uint64_t idle_us);

    void setMaxHosts(size_t n);
    size_t size();
    void clear();

    // SEC-11: Defensible in-memory bounds to prevent DoS from spoofed addresses
    static constexpr size_t kMaxDistinctPerHost = 256;
    static constexpr size_t kMaxPortsPerHost = 256;
    static constexpr uint64_t kWindowUs = 10ull * 1000000ull;      // victim window
    static constexpr size_t kMaxSrcPerWindow = 5000;               // per victim
    static constexpr size_t kMaxSrcEntriesTotal = 100000;          // across all victims

private:
    HostProfiler() = default;

    // Bounded LRU hash table: front = most recently used.
    template <class K, class V, class H>
    class LruTable {
    public:
        struct Entry { V value; typename std::list<K>::iterator it; };

        V& touch(const K& key, size_t max_size, const std::function<void(V&)>& on_evict, bool* created = nullptr) {
            auto found = map_.find(key);
            if (found != map_.end()) {
                lru_.splice(lru_.begin(), lru_, found->second.it);
                if (created) *created = false;
                return found->second.value;
            }
            while (!map_.empty() && map_.size() >= max_size) evictBack(on_evict);
            lru_.push_front(key);
            auto ins = map_.emplace(key, Entry{V{}, lru_.begin()}).first;
            if (created) *created = true;
            return ins->second.value;
        }
        V* find(const K& key) {
            auto f = map_.find(key);
            return f == map_.end() ? nullptr : &f->second.value;
        }
        // Pop entries from the cold end while pred(value) is true.
        size_t expire(const std::function<bool(const V&)>& pred, const std::function<void(V&)>& on_evict) {
            size_t n = 0;
            while (!lru_.empty()) {
                auto f = map_.find(lru_.back());
                if (f == map_.end()) { lru_.pop_back(); continue; }
                if (!pred(f->second.value)) break;
                if (on_evict) on_evict(f->second.value);
                map_.erase(f);
                lru_.pop_back();
                ++n;
            }
            return n;
        }
        size_t size() const { return map_.size(); }
        void clear(const std::function<void(V&)>& on_evict = nullptr) {
            if (on_evict) for (auto& kv : map_) on_evict(kv.second.value);
            map_.clear();
            lru_.clear();
        }
    private:
        void evictBack(const std::function<void(V&)>& on_evict) {
            auto f = map_.find(lru_.back());
            if (f != map_.end()) {
                if (on_evict) on_evict(f->second.value);
                map_.erase(f);
            }
            lru_.pop_back();
        }
        std::unordered_map<K, Entry, H> map_;
        std::list<K> lru_;
    };

    // ---- source host ----
    struct HostStats {
        std::unordered_set<IPAddress, IPAddressHash> dst_ips;
        std::unordered_set<uint16_t> dst_ports;
        uint64_t last_connection_us = 0;
        uint64_t last_activity_us = 0;
        size_t connection_count = 0;
        size_t iat_samples = 0;
        double mean_ms = 0.0;
        double m2 = 0.0;                      // Welford running sum of squared deviations
    };

    // ---- victim ----
    struct Window {
        uint64_t start_us = 0, last_us = 0;
        uint64_t flows = 0, pkts = 0, bytes = 0;
        std::unordered_map<IPAddress, uint32_t, IPAddressHash> srcs;   // src -> new flows in window
        uint64_t overflow = 0;                // sources beyond the cap, each counted once
        double s_clogc = 0.0;                 // sum over sources of c*ln(c)
    };
    struct VictimStats {
        Window cur;
        VictimSummary peak;                   // busiest completed window
        uint64_t peak_flows = 0;
        uint64_t peak_start_us = 0;
        uint64_t last_activity_us = 0;
    };

    // ---- pair ----
    struct PairKey {
        IPAddress src, dst;
        uint16_t dport = 0;
        uint8_t proto = 0;
        bool operator==(const PairKey& o) const {
            return dport == o.dport && proto == o.proto && src == o.src && dst == o.dst;
        }
    };
    struct PairKeyHash {
        size_t operator()(const PairKey& k) const {
            IPAddressHash ih;
            uint64_t h = hashMix(hashSeed() ^ ih(k.src));
            h = hashMix(h ^ (ih(k.dst) + 0x9e3779b97f4a7c15ULL));
            h = hashMix(h ^ ((static_cast<uint64_t>(k.dport) << 8) | k.proto));
            return static_cast<size_t>(h);
        }
    };
    struct PairStats {
        uint64_t count = 0;
        uint64_t last_start_us = 0;
        uint64_t last_activity_us = 0;
        size_t iat_samples = 0;
        double mean_ms = 0.0;
        double m2 = 0.0;
    };

    void advanceWindow(VictimStats& v, uint64_t ts_us);
    static VictimSummary summarize(const Window& w);
    void releaseWindow(VictimStats& v);

    std::mutex mutex_;
    LruTable<IPAddress, HostStats, IPAddressHash> hosts_;
    LruTable<IPAddress, VictimStats, IPAddressHash> victims_;
    LruTable<PairKey, PairStats, PairKeyHash> pairs_;
    size_t max_hosts_ = 200000;
    size_t max_victims_ = 100000;
    size_t max_pairs_ = 200000;
    size_t src_entries_total_ = 0;
};

} // namespace DPI

#endif // HOST_PROFILER_H
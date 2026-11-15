#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include <chrono>
#include <functional>
#include <list>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace DPI {

// ============================================================================
// Connection Tracker - flow table
// ============================================================================
//  * Bidirectional: a packet and its reply map to the same Connection.
//  * O(1) everywhere. Flows sit in an LRU list (front = most recent), so
//    evicting the oldest flow no longer scans the whole table. The old scan
//    made every new flow past the cap cost O(max_connections), which a
//    spoofed-source SYN flood turned into a hang of the monitor itself.
//  * Time is the packet timestamp (microseconds), never the wall clock.
//  * A flow that is evicted or expired is handed to a callback first, so the
//    caller can export it before it disappears.
// ============================================================================
class ConnectionTracker {
public:
    using FlowCallback = std::function<void(Connection&)>;

    // The first kMaxSequence packets of a flow keep their size/gap sequence.
    static constexpr size_t kMaxSequence = 15;

    ConnectionTracker(int fp_id, size_t max_connections = 100000);

    // Called for a flow that is evicted because the table is full.
    void setEvictCallback(FlowCallback cb) { on_evict_ = std::move(cb); }

    // Get or create the flow for this tuple (a reply finds the original flow).
    // *created tells whether a new entry was made.
    Connection* getOrCreateConnection(const FiveTuple& tuple, uint64_t ts_us, bool* created = nullptr);

    // Existing connection or nullptr (checks the reverse tuple too).
    Connection* getConnection(const FiveTuple& tuple);

    // Account one packet. frame_bytes = L2+L3 bytes without padding,
    // payload_len = transport payload (for the size/gap sequence).
    void updateConnection(Connection* conn, uint64_t ts_us, size_t frame_bytes, size_t payload_len,
                          bool is_outbound, uint8_t tcp_flags = 0);

    void classifyConnection(Connection* conn, AppType app, const std::string& sni);
    void blockConnection(Connection* conn);
    void closeConnection(const FiveTuple& tuple);
    bool removeConnection(const FiveTuple& tuple);

    // Expire flows by PACKET time. A flow goes when it has been idle for
    // idle_timeout_us, or when it saw FIN/RST and has been quiet for
    // close_grace_us. on_expire runs before removal. Returns flows removed.
    size_t expire(uint64_t now_us, uint64_t idle_timeout_us, uint64_t close_grace_us,
                  const FlowCallback& on_expire);

    // Hand every remaining flow (oldest first) to cb, then empty the table.
    size_t flushAll(const FlowCallback& cb);

    std::vector<Connection> getAllConnections() const;
    size_t getActiveCount() const;

    struct TrackerStats {
        size_t active_connections;
        size_t total_connections_seen;
        size_t classified_connections;
        size_t blocked_connections;
        size_t evicted_connections;
    };
    TrackerStats getStats() const;

    void clear();
    void forEach(std::function<void(const Connection&)> callback) const;
    void forEachDirtyAndClear(std::function<void(const Connection&)> callback);

private:
    struct Entry {
        Connection conn;
        std::list<FiveTuple>::iterator lru_it;
    };

    void touch(const FiveTuple& key);
    void evictOldest();

    int fp_id_;
    size_t max_connections_;

    std::unordered_map<FiveTuple, Entry, FiveTupleHash> connections_;
    std::list<FiveTuple> lru_;
    FlowCallback on_evict_;

    size_t total_seen_ = 0;
    size_t classified_count_ = 0;
    size_t blocked_count_ = 0;
    size_t evicted_count_ = 0;
};

// ============================================================================
// Global Connection Table - aggregates stats from several trackers
// ============================================================================
class GlobalConnectionTable {
public:
    GlobalConnectionTable(size_t num_fps);

    void registerTracker(int fp_id, ConnectionTracker* tracker);

    struct GlobalStats {
        size_t total_active_connections;
        size_t total_connections_seen;
        std::unordered_map<AppType, size_t> app_distribution;
        std::vector<std::pair<std::string, size_t>> top_domains;
    };

    GlobalStats getGlobalStats() const;
    std::string generateReport() const;

private:
    std::vector<ConnectionTracker*> trackers_;
    mutable std::shared_mutex mutex_;
};

} // namespace DPI

#endif // CONNECTION_TRACKER_H

/**
 * @file connection_tracker.cpp
 * @brief Stateful, bidirectional flow table with O(1) lookup, LRU eviction and
 *        packet-time based expiry.
 */

#include "connection_tracker.h"
#include <algorithm>
#include <climits>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <sstream>

namespace DPI {

namespace {
constexpr uint8_t kFIN = 0x01, kSYN = 0x02, kRST = 0x04, kACK = 0x10;
}

// ============================================================================
// ConnectionTracker
// ============================================================================

ConnectionTracker::ConnectionTracker(int fp_id, size_t max_connections)
    : fp_id_(fp_id), max_connections_(max_connections ? max_connections : 1) {
}

void ConnectionTracker::touch(const FiveTuple& key) {
    auto it = connections_.find(key);
    if (it != connections_.end()) {
        lru_.splice(lru_.begin(), lru_, it->second.lru_it);
    }
}

Connection* ConnectionTracker::getOrCreateConnection(const FiveTuple& tuple, uint64_t ts_us, bool* created) {
    if (created) *created = false;

    if (Connection* existing = getConnection(tuple)) return existing;

    // Make room first. O(1): the victim is the tail of the LRU list.
    while (connections_.size() >= max_connections_) evictOldest();

    lru_.push_front(tuple);
    Entry entry;
    entry.lru_it = lru_.begin();
    entry.conn.tuple = tuple;
    entry.conn.state = ConnectionState::NEW;
    entry.conn.first_seen_us = ts_us;
    entry.conn.last_seen_us = ts_us;
    entry.conn.last_export_us = ts_us;

    auto result = connections_.emplace(tuple, std::move(entry));
    ++total_seen_;
    if (created) *created = true;
    return &result.first->second.conn;
}

Connection* ConnectionTracker::getConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it != connections_.end()) return &it->second.conn;

    auto rev = connections_.find(tuple.reverse());
    if (rev != connections_.end()) return &rev->second.conn;
    return nullptr;
}

void ConnectionTracker::updateConnection(Connection* conn, uint64_t ts_us, size_t frame_bytes,
                                         size_t payload_len, bool is_outbound, uint8_t tcp_flags) {
    if (!conn) return;

    touch(conn->tuple);

    // Size / gap sequence of the first kMaxSequence packets. Gaps come from
    // the packet timestamps, so a capture replayed at full speed keeps the
    // timing it was recorded with.
    if (conn->packet_sizes.size() < kMaxSequence) {
        int size = static_cast<int>(std::min<size_t>(payload_len, INT_MAX));
        if (!is_outbound) size = -size;
        conn->packet_sizes.push_back(size);

        uint64_t gap_ms = 0;
        if (conn->packet_sizes.size() > 1 && ts_us > conn->last_seen_us) {
            gap_ms = (ts_us - conn->last_seen_us) / 1000;
        }
        conn->inter_packet_times_ms.push_back(static_cast<uint32_t>(std::min<uint64_t>(gap_ms, UINT32_MAX)));
    }

    if (ts_us > conn->last_seen_us) conn->last_seen_us = ts_us;  // tolerate out-of-order timestamps

    if (is_outbound) {
        conn->packets_out++;
        conn->bytes_out += frame_bytes;
    } else {
        conn->packets_in++;
        conn->bytes_in += frame_bytes;
    }

    if (tcp_flags & kSYN) {
        if (tcp_flags & kACK) {
            conn->syn_ack_count++;
            conn->syn_ack_seen = true;
        } else {
            conn->syn_count++;
            conn->syn_seen = true;
        }
    }
    if (tcp_flags & kFIN) {
        conn->fin_count++;
        conn->fin_seen = true;
    }
    if (tcp_flags & kRST) {
        conn->rst_count++;
        conn->rst_seen = true;
    }

    conn->dirty = true;
}

void ConnectionTracker::classifyConnection(Connection* conn, AppType app, const std::string& sni) {
    if (!conn) return;
    if (conn->state != ConnectionState::CLASSIFIED) {
        conn->app_type = app;
        if (!sni.empty()) conn->sni = sni;
        conn->state = ConnectionState::CLASSIFIED;
        conn->dirty = true;
        classified_count_++;
    } else {
        // Refine classification if previously generic
        if (conn->app_type == AppType::UNKNOWN || conn->app_type == AppType::HTTPS || conn->app_type == AppType::DNS) {
            if (app != AppType::UNKNOWN && app != AppType::HTTPS && app != AppType::DNS) {
                conn->app_type = app;
                conn->dirty = true;
            }
        }
        if (conn->sni.empty() && !sni.empty()) {
            conn->sni = sni;
            conn->dirty = true;
        }
    }
}

void ConnectionTracker::blockConnection(Connection* conn) {
    if (!conn) return;
    conn->state = ConnectionState::BLOCKED;
    conn->action = PacketAction::DROP;
    blocked_count_++;
}

void ConnectionTracker::closeConnection(const FiveTuple& tuple) {
    if (Connection* c = getConnection(tuple)) c->state = ConnectionState::CLOSED;
}

bool ConnectionTracker::removeConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it == connections_.end()) it = connections_.find(tuple.reverse());
    if (it == connections_.end()) return false;
    lru_.erase(it->second.lru_it);
    connections_.erase(it);
    return true;
}

void ConnectionTracker::evictOldest() {
    if (lru_.empty()) return;
    auto it = connections_.find(lru_.back());
    if (it != connections_.end()) {
        if (on_evict_) on_evict_(it->second.conn);
        connections_.erase(it);
    }
    lru_.pop_back();
    ++evicted_count_;
}

size_t ConnectionTracker::expire(uint64_t now_us, uint64_t idle_timeout_us, uint64_t close_grace_us,
                                 const FlowCallback& on_expire) {
    size_t removed = 0;
    // Walk from the least recently used end. Idle time only shrinks as we go
    // towards the front, so we can stop at the first flow quieter than the
    // grace period.
    auto it = lru_.end();
    while (it != lru_.begin()) {
        --it;
        auto entry = connections_.find(*it);
        if (entry == connections_.end()) { it = lru_.erase(it); continue; }

        Connection& c = entry->second.conn;
        const uint64_t idle = now_us > c.last_seen_us ? now_us - c.last_seen_us : 0;
        if (idle < close_grace_us) break;

        const bool closing = c.fin_seen || c.rst_seen || c.state == ConnectionState::CLOSED;
        if (closing || idle >= idle_timeout_us) {
            if (on_expire) on_expire(c);
            connections_.erase(entry);
            it = lru_.erase(it);  // returns the element after; --it above moves to the one before
            ++removed;
        }
    }
    return removed;
}

size_t ConnectionTracker::flushAll(const FlowCallback& cb) {
    size_t n = 0;
    for (auto it = lru_.rbegin(); it != lru_.rend(); ++it) {
        auto entry = connections_.find(*it);
        if (entry == connections_.end()) continue;
        if (cb) cb(entry->second.conn);
        ++n;
    }
    connections_.clear();
    lru_.clear();
    return n;
}

std::vector<Connection> ConnectionTracker::getAllConnections() const {
    std::vector<Connection> result;
    result.reserve(connections_.size());
    for (const auto& pair : connections_) result.push_back(pair.second.conn);
    return result;
}

size_t ConnectionTracker::getActiveCount() const {
    return connections_.size();
}

ConnectionTracker::TrackerStats ConnectionTracker::getStats() const {
    TrackerStats stats;
    stats.active_connections = connections_.size();
    stats.total_connections_seen = total_seen_;
    stats.classified_connections = classified_count_;
    stats.blocked_connections = blocked_count_;
    stats.evicted_connections = evicted_count_;
    return stats;
}

void ConnectionTracker::clear() {
    connections_.clear();
    lru_.clear();
}

void ConnectionTracker::forEach(std::function<void(const Connection&)> callback) const {
    for (const auto& pair : connections_) callback(pair.second.conn);
}

void ConnectionTracker::forEachDirtyAndClear(std::function<void(const Connection&)> callback) {
    for (auto& pair : connections_) {
        if (pair.second.conn.dirty) {
            callback(pair.second.conn);
            pair.second.conn.dirty = false;
        }
    }
}

// ============================================================================
// GlobalConnectionTable
// ============================================================================

GlobalConnectionTable::GlobalConnectionTable(size_t num_fps) {
    trackers_.resize(num_fps, nullptr);
}

void GlobalConnectionTable::registerTracker(int fp_id, ConnectionTracker* tracker) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (fp_id >= 0 && fp_id < static_cast<int>(trackers_.size())) {
        trackers_[fp_id] = tracker;
    }
}

GlobalConnectionTable::GlobalStats GlobalConnectionTable::getGlobalStats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    GlobalStats stats;
    stats.total_active_connections = 0;
    stats.total_connections_seen = 0;

    std::unordered_map<std::string, size_t> domain_counts;

    for (const auto* tracker : trackers_) {
        if (!tracker) continue;

        auto tracker_stats = tracker->getStats();
        stats.total_active_connections += tracker_stats.active_connections;
        stats.total_connections_seen += tracker_stats.total_connections_seen;

        tracker->forEach([&](const Connection& conn) {
            stats.app_distribution[conn.app_type]++;
            if (!conn.sni.empty()) domain_counts[conn.sni]++;
        });
    }

    std::vector<std::pair<std::string, size_t>> domain_vec(domain_counts.begin(), domain_counts.end());
    std::sort(domain_vec.begin(), domain_vec.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    const size_t count = std::min(domain_vec.size(), static_cast<size_t>(20));
    stats.top_domains.assign(domain_vec.begin(), domain_vec.begin() + static_cast<std::ptrdiff_t>(count));
    return stats;
}

std::string GlobalConnectionTable::generateReport() const {
    auto stats = getGlobalStats();

    std::ostringstream ss;
    ss << "\n=== CONNECTION STATISTICS REPORT ===\n";
    ss << "Active Connections:     " << std::setw(10) << stats.total_active_connections << "\n";
    ss << "Total Connections Seen: " << std::setw(10) << stats.total_connections_seen << "\n";
    ss << "\n--- Application breakdown ---\n";

    size_t total = 0;
    for (const auto& pair : stats.app_distribution) total += pair.second;

    std::vector<std::pair<AppType, size_t>> sorted_apps(stats.app_distribution.begin(), stats.app_distribution.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (const auto& pair : sorted_apps) {
        const double pct = total > 0 ? (100.0 * static_cast<double>(pair.second) / static_cast<double>(total)) : 0;
        ss << std::left << std::setw(20) << appTypeToString(pair.first)
           << std::right << std::setw(10) << pair.second
           << " (" << std::fixed << std::setprecision(1) << std::setw(5) << pct << "%)\n";
    }

    if (!stats.top_domains.empty()) {
        ss << "\n--- Top domains ---\n";
        for (const auto& pair : stats.top_domains) {
            std::string domain = pair.first;
            if (domain.length() > 35) domain = domain.substr(0, 32) + "...";
            ss << std::left << std::setw(40) << domain << std::right << std::setw(10) << pair.second << "\n";
        }
    }
    return ss.str();
}

} // namespace DPI

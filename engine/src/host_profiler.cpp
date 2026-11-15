#include "host_profiler.h"
#include <algorithm>
#include <cmath>

namespace DPI {

namespace {
inline double clogc(double c) { return c > 0.0 ? c * std::log(c) : 0.0; }

// Welford step over a stream of gaps.
inline void welford(size_t& n, double& mean, double& m2, double x) {
    ++n;
    const double delta = x - mean;
    mean += delta / static_cast<double>(n);
    m2 += delta * (x - mean);
}
} // namespace

void HostProfiler::releaseWindow(VictimStats& v) {
    src_entries_total_ -= std::min(src_entries_total_, v.cur.srcs.size());
}

VictimSummary HostProfiler::summarize(const Window& w) {
    VictimSummary s;
    if (w.flows == 0 && w.pkts == 0) return s;
    const double elapsed_s = std::max(static_cast<double>(w.last_us > w.start_us ? w.last_us - w.start_us : 0) / 1e6, 1.0);
    s.distinct_srcs = w.srcs.size() + static_cast<size_t>(w.overflow);
    s.flows_per_s = static_cast<double>(w.flows) / elapsed_s;
    s.pkts_per_s = static_cast<double>(w.pkts) / elapsed_s;
    s.bytes_per_s = static_cast<double>(w.bytes) / elapsed_s;
    if (w.flows > 1) {
        const double n = static_cast<double>(w.flows);
        const double h = (std::log(n) - w.s_clogc / n) / std::log(2.0);
        s.src_entropy_bits = h > 0.0 ? h : 0.0;
    }
    return s;
}

// Roll the tumbling window forward. The finished window becomes the "peak" if
// it was the busiest one seen recently.
void HostProfiler::advanceWindow(VictimStats& v, uint64_t ts_us) {
    Window& w = v.cur;
    if (w.flows == 0 && w.pkts == 0) { w.start_us = w.last_us = ts_us; return; }
    if (ts_us < w.start_us + kWindowUs) return;

    // Peak goes stale after six windows without being beaten.
    if (v.peak_flows > 0 && w.start_us > v.peak_start_us + 6 * kWindowUs) {
        v.peak = VictimSummary{};
        v.peak_flows = 0;
    }
    if (w.flows >= v.peak_flows && w.flows > 0) {
        v.peak = summarize(w);
        v.peak_flows = w.flows;
        v.peak_start_us = w.start_us;
    }
    releaseWindow(v);
    v.cur = Window{};
    v.cur.start_us = v.cur.last_us = ts_us;
}

void HostProfiler::recordNewConnection(const IPAddress& src, const IPAddress& dst, uint16_t dst_port,
                                       uint8_t protocol, uint64_t ts_us) {
    std::lock_guard<std::mutex> lock(mutex_);

    // ---- source host ----
    // A spoofed-source flood creates a host per packet, hence the LRU bound.
    {
        HostStats& s = hosts_.touch(src, max_hosts_, nullptr);
        if (s.dst_ips.size() < kMaxDistinctPerHost) s.dst_ips.insert(dst);
        if (s.dst_ports.size() < kMaxPortsPerHost) s.dst_ports.insert(dst_port);

        // Welford over the gaps between this host's new flows (n = gaps).
        if (s.connection_count > 0) {
            const double x = (ts_us >= s.last_connection_us)
                                 ? static_cast<double>(ts_us - s.last_connection_us) / 1000.0
                                 : 0.0;
            welford(s.iat_samples, s.mean_ms, s.m2, x);
        }
        ++s.connection_count;
        if (ts_us > s.last_connection_us) s.last_connection_us = ts_us;
        if (ts_us > s.last_activity_us) s.last_activity_us = ts_us;
    }

    // ---- victim ----
    {
        VictimStats& v = victims_.touch(dst, max_victims_, [this](VictimStats& e) { releaseWindow(e); });
        advanceWindow(v, ts_us);
        Window& w = v.cur;
        ++w.flows;
        if (ts_us > w.last_us) w.last_us = ts_us;
        auto it = w.srcs.find(src);
        if (it != w.srcs.end()) {
            const double c = static_cast<double>(it->second);
            w.s_clogc += clogc(c + 1.0) - clogc(c);
            ++it->second;
        } else if (w.srcs.size() < kMaxSrcPerWindow && src_entries_total_ < kMaxSrcEntriesTotal) {
            w.srcs.emplace(src, 1u);   // a count of 1 adds c*ln(c) = 0
            ++src_entries_total_;
        } else {
            ++w.overflow;              // untracked source, treated as unique
        }
        if (ts_us > v.last_activity_us) v.last_activity_us = ts_us;
    }

    // ---- pair history (beaconing) ----
    {
        PairKey key;
        key.src = src; key.dst = dst; key.dport = dst_port; key.proto = protocol;
        PairStats& p = pairs_.touch(key, max_pairs_, nullptr);
        if (p.count > 0) {
            const double x = (ts_us >= p.last_start_us)
                                 ? static_cast<double>(ts_us - p.last_start_us) / 1000.0
                                 : 0.0;
            welford(p.iat_samples, p.mean_ms, p.m2, x);
        }
        ++p.count;
        if (ts_us > p.last_start_us) p.last_start_us = ts_us;
        if (ts_us > p.last_activity_us) p.last_activity_us = ts_us;
    }
}

void HostProfiler::recordPacket(const IPAddress& dst, uint32_t frame_bytes, uint64_t ts_us) {
    std::lock_guard<std::mutex> lock(mutex_);
    VictimStats* v = victims_.find(dst);
    if (!v) return;
    advanceWindow(*v, ts_us);
    ++v->cur.pkts;
    v->cur.bytes += frame_bytes;
    if (ts_us > v->cur.last_us) v->cur.last_us = ts_us;
    if (ts_us > v->last_activity_us) v->last_activity_us = ts_us;
}

HostSummary HostProfiler::getStats(const IPAddress& src) {
    std::lock_guard<std::mutex> lock(mutex_);
    HostSummary out;
    const HostStats* s = hosts_.find(src);
    if (!s) return out;
    out.distinct_dst_ips = s->dst_ips.size();
    out.distinct_dst_ports = s->dst_ports.size();
    out.mean_inter_arrival_ms = s->mean_ms;
    out.var_inter_arrival_ms = s->iat_samples > 1 ? s->m2 / static_cast<double>(s->iat_samples - 1) : 0.0;
    out.connection_count = s->connection_count;
    return out;
}

VictimSummary HostProfiler::getVictim(const IPAddress& dst) {
    std::lock_guard<std::mutex> lock(mutex_);
    const VictimStats* v = victims_.find(dst);
    if (!v) return {};
    if (v->cur.flows >= v->peak_flows) return summarize(v->cur);
    return v->peak;
}

PairSummary HostProfiler::getPair(const IPAddress& src, const IPAddress& dst, uint16_t dst_port, uint8_t protocol) {
    std::lock_guard<std::mutex> lock(mutex_);
    PairKey key;
    key.src = src; key.dst = dst; key.dport = dst_port; key.proto = protocol;
    PairSummary out;
    const PairStats* p = pairs_.find(key);
    if (!p) return out;
    out.flow_count = static_cast<size_t>(p->count);
    out.interval_mean_ms = p->mean_ms;
    if (p->iat_samples > 1) out.interval_std_ms = std::sqrt(p->m2 / static_cast<double>(p->iat_samples - 1));
    if (out.interval_mean_ms > 0.0) out.interval_cv = out.interval_std_ms / out.interval_mean_ms;
    return out;
}

size_t HostProfiler::expireIdle(uint64_t now_us, uint64_t idle_us) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto stale = [&](uint64_t last) { return now_us > last && now_us - last >= idle_us; };
    size_t removed = 0;
    removed += hosts_.expire([&](const HostStats& s) { return stale(s.last_activity_us); }, nullptr);
    removed += victims_.expire([&](const VictimStats& v) { return stale(v.last_activity_us); },
                               [this](VictimStats& e) { releaseWindow(e); });
    removed += pairs_.expire([&](const PairStats& p) { return stale(p.last_activity_us); }, nullptr);
    return removed;
}

void HostProfiler::setMaxHosts(size_t n) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_hosts_ = n ? n : 1;
}

size_t HostProfiler::size() {
    std::lock_guard<std::mutex> lock(mutex_);
    return hosts_.size();
}

void HostProfiler::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    hosts_.clear();
    victims_.clear();
    pairs_.clear();
    src_entries_total_ = 0;
}

} // namespace DPI
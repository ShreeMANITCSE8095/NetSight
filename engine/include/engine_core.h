#ifndef NETSIGHT_ENGINE_CORE_H
#define NETSIGHT_ENGINE_CORE_H

#include "types.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "live_capture.h"
#include "tls_extractor.h"
#include "dns_parser.h"
#include "host_profiler.h"
#include "connection_tracker.h"
#include "rule_manager.h"
#include "tcp_server.h"

#include <memory>
#include <string>
#include <atomic>
#include <chrono>

namespace DPI {

struct EngineConfig {
    std::string mode = "replay"; // "replay", "live", "analyze"
    std::string pcap_file;
    std::string output_file;
    std::string interface_name;
    std::string rules_file = "rules.json";
    std::string tcp_host = "127.0.0.1";
    uint16_t tcp_port = 9999;
    double replay_speed = 1.0;   // 1.0 = real-time, 0 = as fast as possible
    bool loop_replay = true;
    uint32_t export_interval_ms = 1000;
};

class EngineCore {
public:
    explicit EngineCore(EngineConfig config);
    ~EngineCore();

    EngineCore(const EngineCore&) = delete;
    EngineCore& operator=(const EngineCore&) = delete;

    // Run the engine according to configured mode
    bool run();
    void stop();

    // Helper: export a connection to JSON
    static std::string formatFlowJson(const Connection& conn, const std::string& record_type = "flow");
    static std::string formatStatsJson(uint64_t total_packets, uint64_t total_bytes,
                                       size_t active_flows, size_t total_flows,
                                       double pps, double bps,
                                       const std::string& mode = "replay",
                                       int64_t dropped_packets = -1);

    // Offline PCAP analysis mode (replaces legacy dpi_json / server.py backend)
    bool runBatchAnalysis(const std::string& input_file, const std::string& output_file);

private:
    void processPacket(const PacketAnalyzer::RawPacket& raw);
    bool runReplayLoop();
    bool runLiveCapture();

    EngineConfig config_;
    std::atomic<bool> running_{false};

    std::unique_ptr<ConnectionTracker> tracker_;
    std::unique_ptr<RuleManager> rules_;
    std::unique_ptr<TcpServer> tcp_server_;

    // Performance & health counters
    uint32_t generation_ = 0;
    uint64_t total_packets_ = 0;
    uint64_t total_bytes_ = 0;
    uint64_t period_packets_ = 0;
    uint64_t period_bytes_ = 0;
    std::chrono::steady_clock::time_point last_export_time_;
    std::chrono::steady_clock::time_point last_rules_poll_;

    // IP to domain resolution cache populated from DNS response (A records)
    std::unordered_map<uint32_t, std::string> dns_ip_cache_;
};

} // namespace DPI

#endif // NETSIGHT_ENGINE_CORE_H


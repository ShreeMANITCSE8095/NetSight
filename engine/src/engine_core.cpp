#include "engine_core.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <thread>
#include <fstream>
#include <algorithm>

namespace DPI {

namespace {

std::string jsonEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
            out += buf;
        } else {
            out += c;
        }
    }
    return out;
}

double finite(double v) {
    return std::isfinite(v) ? v : 0.0;
}

} // namespace

EngineCore::EngineCore(EngineConfig config)
    : config_(std::move(config)) {
    tracker_ = std::make_unique<ConnectionTracker>(0, 100000);
    rules_ = std::make_unique<RuleManager>();

    if (config_.mode != "analyze") {
        tcp_server_ = std::make_unique<TcpServer>(config_.tcp_host, config_.tcp_port);
    }

    // Load initial rules if file exists
    if (!config_.rules_file.empty()) {
        rules_->loadFromFile(config_.rules_file);
    }
}

EngineCore::~EngineCore() {
    stop();
}

void EngineCore::stop() {
    running_ = false;
    if (tcp_server_) {
        tcp_server_->stop();
    }
}

std::string EngineCore::formatFlowJson(const Connection& conn, const std::string& record_type) {
    HostProfiler& prof = HostProfiler::getInstance();
    const HostSummary host = prof.getStats(conn.tuple.src_ip);

    uint64_t duration_ms = conn.last_seen_us > conn.first_seen_us ? (conn.last_seen_us - conn.first_seen_us) / 1000 : 0;
    double byte_ratio = conn.bytes_in > 0 ? static_cast<double>(conn.bytes_out) / static_cast<double>(conn.bytes_in) : 0.0;

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::ostringstream ss;
    ss.imbue(std::locale::classic());

    ss << "{"
       << "\"v\":1,"
       << "\"type\":\"" << record_type << "\","
       << "\"generation\":" << conn.generation << ","
       << "\"ts\":" << now_ms << ","
       << "\"flow_id\":\"" << jsonEscape(conn.tuple.toString()) << "\","
       << "\"src_ip\":\"" << jsonEscape(conn.tuple.src_ip.toString()) << "\","
       << "\"dst_ip\":\"" << jsonEscape(conn.tuple.dst_ip.toString()) << "\","
       << "\"src_port\":" << conn.tuple.src_port << ","
       << "\"dst_port\":" << conn.tuple.dst_port << ","
       << "\"proto\":\"" << (conn.tuple.protocol == 6 ? "TCP" : conn.tuple.protocol == 17 ? "UDP" : "OTHER") << "\","
       << "\"app\":\"" << jsonEscape(appTypeToString(conn.app_type)) << "\","
       << "\"sni\":\"" << jsonEscape(conn.sni) << "\","
       << "\"ja3\":\"" << jsonEscape(conn.ja3_fingerprint) << "\","
       << "\"packets_in\":" << conn.packets_in << ","
       << "\"packets_out\":" << conn.packets_out << ","
       << "\"packets_total\":" << (conn.packets_in + conn.packets_out) << ","
       << "\"bytes_in\":" << conn.bytes_in << ","
       << "\"bytes_out\":" << conn.bytes_out << ","
       << "\"bytes_total\":" << (conn.bytes_in + conn.bytes_out) << ","
       << "\"byte_ratio\":" << finite(byte_ratio) << ","
       << "\"duration_ms\":" << duration_ms << ","
       << "\"first_seen\":" << (conn.first_seen_us / 1000) << ","
       << "\"last_seen\":" << (conn.last_seen_us / 1000) << ","
       << "\"syn_count\":" << conn.syn_count << ","
       << "\"syn_ack_count\":" << conn.syn_ack_count << ","
       << "\"fin_count\":" << conn.fin_count << ","
       << "\"rst_count\":" << conn.rst_count << ","
       << "\"tcp_flags\":\"" << PacketAnalyzer::PacketParser::tcpFlagsToString(conn.last_tcp_flags) << "\",";

    if (!conn.dns_queries.empty()) {
        ss << "\"dns_query\":\"" << jsonEscape(conn.dns_queries.front()) << "\",";
    } else {
        ss << "\"dns_query\":\"\",";
    }

    ss << "\"dns_entropy\":" << finite(conn.dns_query_entropy) << ","
       << "\"dns_record_type\":" << conn.dns_record_type << ","
       << "\"src_distinct_dst_ips\":" << host.distinct_dst_ips << ","
       << "\"src_distinct_dst_ports\":" << host.distinct_dst_ports << ","
       << "\"state\":\"" << (conn.state == ConnectionState::CLOSED ? "closed" : "active") << "\","
       << "\"rule_match\":" << (conn.rule_match ? "true" : "false") << ","
       << "\"rule_reason\":\"" << jsonEscape(conn.rule_reason) << "\""
       << "}";

    return ss.str();
}

std::string EngineCore::formatStatsJson(uint64_t total_packets, uint64_t total_bytes,
                                       size_t active_flows, size_t total_flows,
                                       double pps, double bps,
                                       const std::string& mode,
                                       int64_t dropped_packets) {
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::ostringstream ss;
    ss.imbue(std::locale::classic());

    ss << "{"
       << "\"v\":1,"
       << "\"type\":\"stats\","
       << "\"ts\":" << now_ms << ","
       << "\"mode\":\"" << mode << "\","
       << "\"packets_total\":" << total_packets << ","
       << "\"bytes_total\":" << total_bytes << ","
       << "\"total_packets\":" << total_packets << ","
       << "\"total_bytes\":" << total_bytes << ","
       << "\"active_flows\":" << active_flows << ","
       << "\"total_flows\":" << total_flows << ","
       << "\"pps\":" << finite(pps) << ","
       << "\"bps\":" << finite(bps) << ",";

    if (dropped_packets >= 0) {
        ss << "\"drops\":" << dropped_packets;
    } else {
        ss << "\"drops\":null";
    }

    ss << "}";
    return ss.str();
}

void EngineCore::processPacket(const PacketAnalyzer::RawPacket& raw) {
    PacketAnalyzer::ParsedPacket parsed;
    if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
        return;
    }
    if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp && !parsed.has_icmp)) {
        return;
    }

    total_packets_++;
    total_bytes_ += parsed.frame_bytes;
    period_packets_++;
    period_bytes_ += parsed.frame_bytes;

    FiveTuple forward_tuple;
    forward_tuple.src_ip = parsed.src_ip;
    forward_tuple.dst_ip = parsed.dest_ip;
    forward_tuple.src_port = parsed.src_port;
    forward_tuple.dst_port = parsed.dest_port;
    forward_tuple.protocol = parsed.protocol;

    // E1: Determine flow initiator direction:
    // 1) TCP SYN without ACK: source is initiator
    // 2) TCP SYN-ACK: destination is initiator
    // 3) Ephemeral port (>1024) to service port (<=1024 or 8080/8443): ephemeral is initiator
    // 4) Lower port / IP tie-break
    bool reverse_initiator = false;
    if (parsed.has_tcp && (parsed.tcp_flags & 0x02)) {
        if (parsed.tcp_flags & 0x10) {
            reverse_initiator = true;
        } else {
            reverse_initiator = false;
        }
    } else {
        auto isServerPort = [](uint16_t p) {
            return p <= 1024 || p == 8080 || p == 8443;
        };
        bool src_is_srv = isServerPort(parsed.src_port);
        bool dst_is_srv = isServerPort(parsed.dest_port);
        if (src_is_srv && !dst_is_srv) {
            reverse_initiator = true;
        } else if (!src_is_srv && dst_is_srv) {
            reverse_initiator = false;
        } else if (parsed.src_port > parsed.dest_port) {
            reverse_initiator = false;
        } else if (parsed.src_port < parsed.dest_port) {
            reverse_initiator = true;
        } else {
            reverse_initiator = (parsed.dest_ip.toString() < parsed.src_ip.toString());
        }
    }

    FiveTuple canonical_tuple = reverse_initiator ? forward_tuple.reverse() : forward_tuple;
    uint64_t ts_us = static_cast<uint64_t>(raw.header.ts_sec) * 1000000ULL + raw.header.ts_usec;

    bool created = false;
    Connection* conn = tracker_->getOrCreateConnection(canonical_tuple, ts_us, &created);
    if (!conn) return;

    if (created) {
        conn->generation = generation_;
    }

    bool is_outbound = (parsed.src_ip == conn->tuple.src_ip && parsed.src_port == conn->tuple.src_port);
    tracker_->updateConnection(conn, ts_us, parsed.frame_bytes, parsed.payload_length, is_outbound, parsed.tcp_flags);
    conn->last_tcp_flags = parsed.tcp_flags;

    // Host Profiling: attributes connection to initiator (client)
    HostProfiler& profiler = HostProfiler::getInstance();
    if (created) {
        profiler.recordNewConnection(conn->tuple.src_ip, conn->tuple.dst_ip, conn->tuple.dst_port, conn->tuple.protocol, ts_us);
    }
    profiler.recordPacket(conn->tuple.dst_ip, static_cast<uint32_t>(parsed.frame_bytes), ts_us);

    // TLS Inspection (port 443 or general TLS handshake) with fragment reassembly
    if (parsed.has_tcp && (parsed.dest_port == 443 || parsed.dest_port == 8443 || conn->tuple.dst_port == 443 || conn->tuple.dst_port == 8443) &&
        !conn->tls_done && parsed.payload_length > 0) {
        const uint8_t* tls_ptr = parsed.payload_data;
        size_t tls_len = parsed.payload_length;

        if (conn->tls_buf.empty()) {
            if (TLSExtractor::looksLikeClientHelloStart(tls_ptr, tls_len)) {
                if (tls_len <= TLSExtractor::kMaxRecordSize) {
                    conn->tls_buf.assign(tls_ptr, tls_ptr + tls_len);
                    conn->tls_next_seq = parsed.seq_number + static_cast<uint32_t>(tls_len);
                } else {
                    conn->tls_done = true;
                }
            }
        } else {
            // Continuation segment: verify TCP sequence continuity
            if (parsed.seq_number == conn->tls_next_seq) {
                if (conn->tls_buf.size() + tls_len <= TLSExtractor::kMaxRecordSize) {
                    conn->tls_buf.insert(conn->tls_buf.end(), tls_ptr, tls_ptr + tls_len);
                    conn->tls_next_seq += static_cast<uint32_t>(tls_len);
                } else {
                    conn->tls_done = true;
                    conn->tls_buf.clear();
                }
            } else if (parsed.seq_number + static_cast<uint32_t>(tls_len) <= conn->tls_next_seq) {
                // Duplicate / retransmission within already buffered window: ignore
            } else {
                // Out-of-order segment or gap: stop reassembly to prevent corrupting ClientHello
                conn->tls_done = true;
                conn->tls_buf.clear();
            }
        }

        if (!conn->tls_buf.empty()) {
            tls_ptr = conn->tls_buf.data();
            tls_len = conn->tls_buf.size();
            size_t expected = TLSExtractor::expectedRecordSize(tls_ptr, tls_len);
            if (expected > 0 && tls_len >= expected) {
                auto meta = TLSExtractor::extract(tls_ptr, expected);
                conn->tls_done = true;
                conn->tls_buf.clear();
                if (meta) {
                    if (meta->sni) {
                        conn->sni = *meta->sni;
                        conn->app_type = sniToAppType(*meta->sni);
                    } else if (conn->app_type == AppType::UNKNOWN) {
                        conn->app_type = AppType::HTTPS;
                    }
                    conn->ja3_fingerprint = std::move(meta->ja3_fingerprint);
                    tracker_->classifyConnection(conn, conn->app_type, conn->sni);
                }
            }
        }
    }

    // HTTP Inspection (port 80)
    if (parsed.has_tcp && parsed.dest_port == 80 && conn->sni.empty() && parsed.payload_length > 0) {
        auto host = HTTPHostExtractor::extract(parsed.payload_data, parsed.payload_length);
        if (host) {
            conn->sni = *host;
            conn->app_type = sniToAppType(*host);
            tracker_->classifyConnection(conn, conn->app_type, conn->sni);
        } else if (conn->app_type == AppType::UNKNOWN) {
            conn->app_type = AppType::HTTP;
        }
    }

    // DNS Inspection (port 53)
    if (parsed.has_udp && (parsed.dest_port == 53 || parsed.src_port == 53) && parsed.payload_length > 0) {
        conn->app_type = AppType::DNS;
        if (DNSExtractor::isDNSQuery(parsed.payload_data, parsed.payload_length)) {
            auto dns = DNSExtractor::extractQuery(parsed.payload_data, parsed.payload_length);
            if (dns) {
                if (conn->dns_queries.size() < 50) {
                    conn->dns_queries.push_back(dns->domain);
                }
                conn->dns_query_entropy = dns->entropy;
                conn->dns_query_length = dns->domain.length();
                conn->dns_record_type = dns->record_type;
                conn->dns_query_count++;
                if (conn->sni.empty()) {
                    conn->sni = dns->domain;
                }
                tracker_->classifyConnection(conn, AppType::DNS, conn->sni);
            }
        } else if (DNSExtractor::isDNSResponse(parsed.payload_data, parsed.payload_length)) {
            auto resp = DNSExtractor::extractResponse(parsed.payload_data, parsed.payload_length);
            if (resp) {
                for (const auto& ans : resp->answers) {
                    if (dns_ip_cache_.size() > 5000) dns_ip_cache_.clear();
                    dns_ip_cache_[ans.ip_num] = resp->query_domain;
                }
                if (conn->sni.empty() && !resp->query_domain.empty()) {
                    conn->sni = resp->query_domain;
                }
                tracker_->classifyConnection(conn, AppType::DNS, conn->sni);
            }
        }
    }

    // QUIC Inspection (UDP port 443)
    if (parsed.has_udp && (parsed.dest_port == 443 || parsed.src_port == 443)) {
        conn->app_type = AppType::QUIC;
        uint32_t srv_ip_num = 0;
        if (parsed.dest_port == 443 && parsed.dest_ip.family == 4) {
            srv_ip_num = PortableNet::readBE32(parsed.dest_ip.bytes.data());
        } else if (parsed.src_ip.family == 4) {
            srv_ip_num = PortableNet::readBE32(parsed.src_ip.bytes.data());
        }

        if (srv_ip_num != 0) {
            auto it = dns_ip_cache_.find(srv_ip_num);
            if (it != dns_ip_cache_.end()) {
                conn->sni = it->second;
                AppType mapped = sniToAppType(it->second);
                if (mapped != AppType::UNKNOWN && mapped != AppType::HTTPS) {
                    conn->app_type = mapped;
                }
            }
        }
        tracker_->classifyConnection(conn, conn->app_type, conn->sni);
    }

    // Port-based fallback
    if (conn->app_type == AppType::UNKNOWN) {
        if (parsed.dest_port == 443 || parsed.src_port == 443) conn->app_type = parsed.has_udp ? AppType::QUIC : AppType::HTTPS;
        else if (parsed.dest_port == 80 || parsed.src_port == 80) conn->app_type = AppType::HTTP;
        else if (parsed.dest_port == 53 || parsed.src_port == 53) conn->app_type = AppType::DNS;
    }

    // Rule Check (evaluated on classification or rule set change)
    uint32_t current_rules_ver = rules_->getVersion();
    if (!conn->rule_checked || conn->checked_rules_version != current_rules_ver) {
        conn->checked_rules_version = current_rules_ver;
        conn->rule_checked = true;
        auto match_reason = rules_->checkRule(
            conn->tuple.src_ip, conn->tuple.dst_ip,
            conn->tuple.src_port, conn->tuple.dst_port,
            conn->app_type, conn->sni
        );
        if (match_reason) {
            conn->rule_match = true;
            conn->rule_reason = *match_reason;
            conn->state = ConnectionState::ALERTED;
        } else {
            conn->rule_match = false;
            conn->rule_reason.clear();
        }
    }
}

bool EngineCore::runReplayLoop() {
    std::cout << "[Engine] Starting PCAP replay: " << config_.pcap_file
              << " (Speed: " << config_.replay_speed << "x, Loop: " << (config_.loop_replay ? "yes" : "no") << ")\n";

    last_export_time_ = std::chrono::steady_clock::now();
    last_rules_poll_ = std::chrono::steady_clock::now();

    do {
        PacketAnalyzer::PcapReader reader;
        if (!reader.open(config_.pcap_file)) {
            std::cerr << "[Engine] Error opening PCAP file: " << config_.pcap_file << "\n";
            return false;
        }

        PacketAnalyzer::RawPacket raw;
        uint64_t prev_pkt_ts_us = 0;

        while (running_ && reader.readNextPacket(raw)) {
            uint64_t cur_pkt_ts_us = static_cast<uint64_t>(raw.header.ts_sec) * 1000000ULL + raw.header.ts_usec;

            // Replay timing pacing
            if (config_.replay_speed > 0.0 && prev_pkt_ts_us != 0) {
                int64_t gap_us = static_cast<int64_t>(cur_pkt_ts_us - prev_pkt_ts_us);
                if (gap_us > 0 && gap_us < 5000000) { // cap at 5 seconds max idle
                    int64_t sleep_us = static_cast<int64_t>(static_cast<double>(gap_us) / config_.replay_speed);
                    std::this_thread::sleep_for(std::chrono::microseconds(sleep_us));
                }
            }
            prev_pkt_ts_us = cur_pkt_ts_us;

            processPacket(raw);

            // Periodic flow and stats export
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_export_time_).count();
            if (elapsed_ms >= config_.export_interval_ms) {
                // Poll rules
                if (!config_.rules_file.empty()) {
                    rules_->pollFileChanges(config_.rules_file);
                }

                // Push stats
                double pps = (period_packets_ * 1000.0) / elapsed_ms;
                double bps = (period_bytes_ * 8.0 * 1000.0) / elapsed_ms;
                period_packets_ = 0;
                period_bytes_ = 0;

                // Push stats & flows in a single batched buffer (E11)
                std::string batch;
                batch.reserve(8192);
                batch.append(formatStatsJson(
                    total_packets_, total_bytes_, tracker_->getActiveCount(),
                    tracker_->getStats().total_connections_seen, pps, bps, config_.mode, -1
                )).append("\n");

                tracker_->forEachDirtyAndClear([this, &batch](const Connection& conn) {
                    batch.append(formatFlowJson(conn, "flow")).append("\n");
                });

                tracker_->expire(cur_pkt_ts_us, 30000000ULL, 5000000ULL, [this, &batch](Connection& conn) {
                    batch.append(formatFlowJson(conn, "flow_end")).append("\n");
                });

                if (tcp_server_ && !batch.empty()) {
                    tcp_server_->broadcast(batch);
                }

                // Expire idle host profiler records (5 min idle)
                HostProfiler::getInstance().expireIdle(cur_pkt_ts_us, 300000000ULL);

                last_export_time_ = now;
            }
        }

        reader.close();

        // B3: End-of-pass flush: export final stats and any remaining active flows
        auto end_now = std::chrono::steady_clock::now();
        auto end_elapsed_ms = std::max<int64_t>(1, std::chrono::duration_cast<std::chrono::milliseconds>(end_now - last_export_time_).count());
        double final_pps = (period_packets_ * 1000.0) / end_elapsed_ms;
        double final_bps = (period_bytes_ * 8.0 * 1000.0) / end_elapsed_ms;
        period_packets_ = 0;
        period_bytes_ = 0;

        std::string final_batch;
        final_batch.reserve(8192);
        final_batch.append(formatStatsJson(
            total_packets_, total_bytes_, tracker_->getActiveCount(),
            tracker_->getStats().total_connections_seen, final_pps, final_bps, config_.mode, -1
        )).append("\n");

        tracker_->flushAll([this, &final_batch](Connection& conn) {
            conn.state = ConnectionState::CLOSED;
            final_batch.append(formatFlowJson(conn, "flow_end")).append("\n");
        });

        if (tcp_server_ && !final_batch.empty()) {
            tcp_server_->broadcast(final_batch);
        }

        if (config_.loop_replay && running_) {
            std::cout << "[Engine] Replay loop finished. Looping...\n";
            generation_++;
            prev_pkt_ts_us = 0;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    } while (config_.loop_replay && running_);

    return true;
}

bool EngineCore::runLiveCapture() {
    std::string iface = config_.interface_name;
    if (iface.empty()) {
        iface = LiveCapture::getDefaultDevice();
    }

    if (iface.empty()) {
        std::cerr << "[Engine] Error: No network capture interfaces found on this system.\n";
        return false;
    }

    std::cout << "[Engine] Starting LIVE packet capture on adapter: " << iface << "\n";

    LiveCapture capture;
    if (!capture.open(iface)) {
        std::cerr << "[Engine] Failed to open live capture device: " << capture.getLastError() << "\n";
        std::cerr << "[Engine] Note: On Windows, run the terminal as Administrator if access is restricted by Npcap.\n";
        return false;
    }

    std::cout << "[Engine] Live capture active! Inspecting real-time network traffic from your device...\n";

    last_export_time_ = std::chrono::steady_clock::now();
    last_rules_poll_ = std::chrono::steady_clock::now();

    PacketAnalyzer::RawPacket raw;

    while (running_) {
        if (capture.readNextPacket(raw)) {
            processPacket(raw);
        } else if (capture.isErrorOrEof()) {
            std::cerr << "[Engine] Live capture interface stopped: " << capture.getLastError() << "\n";
            break;
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_export_time_).count();
        if (elapsed_ms >= config_.export_interval_ms) {
            // Poll rules
            if (!config_.rules_file.empty()) {
                rules_->pollFileChanges(config_.rules_file);
            }

            // Push stats with real kernel drop counts (E8)
            double pps = (period_packets_ * 1000.0) / elapsed_ms;
            double bps = (period_bytes_ * 8.0 * 1000.0) / elapsed_ms;
            period_packets_ = 0;
            period_bytes_ = 0;

            CaptureStats cstats = capture.getStats();
            int64_t drops = static_cast<int64_t>(cstats.dropped);

            // Push stats & flows in a single batched buffer (E11)
            std::string batch;
            batch.reserve(8192);
            batch.append(formatStatsJson(
                total_packets_, total_bytes_, tracker_->getActiveCount(),
                tracker_->getStats().total_connections_seen, pps, bps, config_.mode, drops
            )).append("\n");

            tracker_->forEachDirtyAndClear([this, &batch](const Connection& conn) {
                batch.append(formatFlowJson(conn, "flow")).append("\n");
            });

            // Expire stale flows (idle > 30s)
            auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            tracker_->expire(now_us, 30000000ULL, 5000000ULL, [this, &batch](Connection& conn) {
                batch.append(formatFlowJson(conn, "flow_end")).append("\n");
            });

            if (tcp_server_ && !batch.empty()) {
                tcp_server_->broadcast(batch);
            }

            // Expire idle host profiler records
            HostProfiler::getInstance().expireIdle(now_us, 300000000ULL);

            last_export_time_ = now;
        }
    }

    // Flush all active flows before exit
    std::string exit_batch;
    exit_batch.reserve(8192);
    tracker_->flushAll([this, &exit_batch](Connection& conn) {
        conn.state = ConnectionState::CLOSED;
        exit_batch.append(formatFlowJson(conn, "flow_end")).append("\n");
    });
    if (tcp_server_ && !exit_batch.empty()) {
        tcp_server_->broadcast(exit_batch);
    }

    capture.close();
    return true;
}

bool EngineCore::run() {
    running_ = true;

    if (tcp_server_ && !tcp_server_->start()) {
        std::cerr << "[Engine] Failed to start TCP streaming server.\n";
        return false;
    }

    if (config_.mode == "replay") {
        return runReplayLoop();
    } else if (config_.mode == "live") {
        return runLiveCapture();
    }

    return true;
}

// Batch analysis mode (replaces legacy dpi_json)
bool EngineCore::runBatchAnalysis(const std::string& input_file, const std::string& output_file) {
    PacketAnalyzer::PcapReader reader;
    if (!reader.open(input_file)) {
        std::cout << "{\"error\":\"Cannot open input file: " << jsonEscape(input_file) << "\"}\n";
        return false;
    }

    std::ofstream output(output_file, std::ios::binary);
    if (output.is_open()) {
        PacketAnalyzer::PcapGlobalHeader out_hdr{};
        out_hdr.magic_number = 0xa1b2c3d4;
        out_hdr.version_major = 2;
        out_hdr.version_minor = 4;
        out_hdr.thiszone = 0;
        out_hdr.sigfigs = 0;
        out_hdr.snaplen = 65535;
        out_hdr.network = reader.isPcapNg() ? 1 : reader.getGlobalHeader().network;
        output.write(reinterpret_cast<const char*>(&out_hdr), sizeof(out_hdr));
    }

    uint64_t forwarded = 0, dropped = 0, tcp_cnt = 0, udp_cnt = 0;
    total_packets_ = 0;
    total_bytes_ = 0;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::vector<Connection> finished_flows;

    PacketAnalyzer::RawPacket raw;
    while (reader.readNextPacket(raw)) {
        total_packets_++;
        PacketAnalyzer::ParsedPacket parsed;
        if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
            total_bytes_ += raw.data.size();
            forwarded++;
            if (output.is_open()) {
                PacketAnalyzer::PcapPacketHeader pkt_hdr;
                pkt_hdr.ts_sec = raw.header.ts_sec;
                pkt_hdr.ts_usec = raw.header.ts_usec;
                pkt_hdr.incl_len = static_cast<uint32_t>(raw.data.size());
                pkt_hdr.orig_len = raw.header.orig_len ? raw.header.orig_len : static_cast<uint32_t>(raw.data.size());
                output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
                output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
            }
            continue;
        }
        total_bytes_ += parsed.frame_bytes;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp && !parsed.has_icmp)) {
            forwarded++;
            if (output.is_open()) {
                PacketAnalyzer::PcapPacketHeader pkt_hdr;
                pkt_hdr.ts_sec = raw.header.ts_sec;
                pkt_hdr.ts_usec = raw.header.ts_usec;
                pkt_hdr.incl_len = static_cast<uint32_t>(raw.data.size());
                pkt_hdr.orig_len = raw.header.orig_len ? raw.header.orig_len : static_cast<uint32_t>(raw.data.size());
                output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
                output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
            }
            continue;
        }

        if (parsed.has_tcp) tcp_cnt++;
        else if (parsed.has_udp) udp_cnt++;

        FiveTuple tuple;
        tuple.src_ip = parsed.src_ip;
        tuple.dst_ip = parsed.dest_ip;
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        uint64_t ts_us = static_cast<uint64_t>(raw.header.ts_sec) * 1000000ULL + raw.header.ts_usec;

        bool created = false;
        Connection* conn = tracker_->getOrCreateConnection(tuple, ts_us, &created);
        if (!conn) continue;

        bool is_outbound = (conn->tuple == tuple);
        tracker_->updateConnection(conn, ts_us, parsed.frame_bytes, parsed.payload_length, is_outbound, parsed.tcp_flags);
        conn->last_tcp_flags = parsed.tcp_flags;

        // TLS inspection
        if (parsed.has_tcp && parsed.dest_port == 443 && !conn->tls_done && parsed.payload_length > 0) {
            auto meta = TLSExtractor::extract(parsed.payload_data, parsed.payload_length);
            if (meta) {
                conn->tls_done = true;
                if (meta->sni) {
                    conn->sni = *meta->sni;
                    conn->app_type = sniToAppType(*meta->sni);
                } else {
                    conn->app_type = AppType::HTTPS;
                }
                conn->ja3_fingerprint = std::move(meta->ja3_fingerprint);
            }
        }

        // HTTP inspection
        if (parsed.has_tcp && parsed.dest_port == 80 && conn->sni.empty() && parsed.payload_length > 0) {
            auto host = HTTPHostExtractor::extract(parsed.payload_data, parsed.payload_length);
            if (host) {
                conn->sni = *host;
                conn->app_type = sniToAppType(*host);
            } else {
                conn->app_type = AppType::HTTP;
            }
        }

        // DNS inspection
        if (parsed.has_udp && (parsed.dest_port == 53 || parsed.src_port == 53) && parsed.payload_length > 0) {
            conn->app_type = AppType::DNS;
            if (DNSExtractor::isDNSQuery(parsed.payload_data, parsed.payload_length)) {
                auto dns = DNSExtractor::extractQuery(parsed.payload_data, parsed.payload_length);
                if (dns) {
                    if (conn->dns_queries.size() < 50) conn->dns_queries.push_back(dns->domain);
                    conn->dns_query_entropy = dns->entropy;
                    conn->dns_query_length = dns->domain.length();
                    conn->dns_record_type = dns->record_type;
                    if (conn->sni.empty()) conn->sni = dns->domain;
                }
            } else if (DNSExtractor::isDNSResponse(parsed.payload_data, parsed.payload_length)) {
                auto resp = DNSExtractor::extractResponse(parsed.payload_data, parsed.payload_length);
                if (resp) {
                    for (const auto& ans : resp->answers) {
                        if (dns_ip_cache_.size() > 5000) dns_ip_cache_.clear();
                        dns_ip_cache_[ans.ip_num] = resp->query_domain;
                    }
                    if (conn->sni.empty() && !resp->query_domain.empty()) {
                        conn->sni = resp->query_domain;
                    }
                }
            }
        }

        // QUIC inspection (UDP port 443)
        if (parsed.has_udp && (parsed.dest_port == 443 || parsed.src_port == 443)) {
            conn->app_type = AppType::QUIC;
            uint32_t srv_ip_num = 0;
            if (parsed.dest_port == 443 && parsed.dest_ip.family == 4) {
                srv_ip_num = PortableNet::readBE32(parsed.dest_ip.bytes.data());
            } else if (parsed.src_ip.family == 4) {
                srv_ip_num = PortableNet::readBE32(parsed.src_ip.bytes.data());
            }

            if (srv_ip_num != 0) {
                auto it = dns_ip_cache_.find(srv_ip_num);
                if (it != dns_ip_cache_.end()) {
                    conn->sni = it->second;
                    AppType mapped = sniToAppType(it->second);
                    if (mapped != AppType::UNKNOWN && mapped != AppType::HTTPS) {
                        conn->app_type = mapped;
                    }
                }
            }
        }

        if (conn->app_type == AppType::UNKNOWN) {
            if (parsed.dest_port == 443 || parsed.src_port == 443) conn->app_type = parsed.has_udp ? AppType::QUIC : AppType::HTTPS;
            else if (parsed.dest_port == 80 || parsed.src_port == 80) conn->app_type = AppType::HTTP;
            else if (parsed.dest_port == 53 || parsed.src_port == 53) conn->app_type = AppType::DNS;
        }

        // Rule check (bidirectional IP & port, suffix domain matching)
        auto rule_reason = rules_->checkRule(
            conn->tuple.src_ip, conn->tuple.dst_ip,
            conn->tuple.src_port, conn->tuple.dst_port,
            conn->app_type, conn->sni
        );
        if (rule_reason) {
            conn->rule_match = true;
            conn->rule_reason = *rule_reason;
            dropped++;
        } else {
            forwarded++;
            if (output.is_open()) {
                PacketAnalyzer::PcapPacketHeader pkt_hdr;
                pkt_hdr.ts_sec = raw.header.ts_sec;
                pkt_hdr.ts_usec = raw.header.ts_usec;
                pkt_hdr.incl_len = static_cast<uint32_t>(raw.data.size());
                pkt_hdr.orig_len = raw.header.orig_len ? raw.header.orig_len : static_cast<uint32_t>(raw.data.size());
                output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
                output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
            }
        }
        app_counts[conn->app_type]++;
    }

    reader.close();
    if (output.is_open()) output.close();

    // Collect all flows
    auto all_conns = tracker_->getAllConnections();

    // Build JSON output
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"summary\": {\n"
       << "    \"total_packets\": " << total_packets_ << ",\n"
       << "    \"total_bytes\": " << total_bytes_ << ",\n"
       << "    \"forwarded\": " << forwarded << ",\n"
       << "    \"dropped\": " << dropped << ",\n"
       << "    \"total_flows\": " << all_conns.size() << ",\n"
       << "    \"tcp_packets\": " << tcp_cnt << ",\n"
       << "    \"udp_packets\": " << udp_cnt << "\n"
       << "  },\n";

    // App distribution (calculated against classified packets)
    std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_counts.begin(), app_counts.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

    uint64_t classified_cnt = tcp_cnt + udp_cnt;
    ss << "  \"app_distribution\": [\n";
    for (size_t i = 0; i < sorted_apps.size(); ++i) {
        double pct = classified_cnt > 0 ? (100.0 * sorted_apps[i].second) / classified_cnt : 0.0;
        ss << "    {\"app\": \"" << appTypeToString(sorted_apps[i].first) << "\", "
           << "\"count\": " << sorted_apps[i].second << ", "
           << "\"percent\": " << std::fixed << std::setprecision(1) << pct << "}";
        if (i + 1 < sorted_apps.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ],\n";

    // Detected domains: prioritize application flows (TLS/HTTP/QUIC) over plain DNS lookups (E4)
    std::vector<std::pair<std::string, std::string>> domains;
    std::unordered_map<std::string, std::string> domain_to_app;
    for (const auto& c : all_conns) {
        if (!c.sni.empty()) {
            if (c.app_type != AppType::DNS) {
                domain_to_app[c.sni] = appTypeToString(c.app_type);
            } else if (domain_to_app.find(c.sni) == domain_to_app.end()) {
                domain_to_app[c.sni] = "DNS";
            }
        }
    }
    for (const auto& pair : domain_to_app) {
        domains.push_back(pair);
    }

    ss << "  \"detected_domains\": [\n";
    for (size_t i = 0; i < domains.size(); ++i) {
        ss << "    {\"domain\": \"" << jsonEscape(domains[i].first) << "\", \"app\": \"" << jsonEscape(domains[i].second) << "\"}";
        if (i + 1 < domains.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ],\n";

    // Top flows by bytes
    std::vector<Connection> sorted_flows = all_conns;
    std::sort(sorted_flows.begin(), sorted_flows.end(), [](const Connection& a, const Connection& b) {
        return (a.bytes_in + a.bytes_out) > (b.bytes_in + b.bytes_out);
    });

    ss << "  \"top_flows\": [\n";
    size_t limit = std::min(sorted_flows.size(), static_cast<size_t>(50));
    for (size_t i = 0; i < limit; ++i) {
        const auto& f = sorted_flows[i];
        ss << "    {\"src\": \"" << f.tuple.src_ip.toString() << ":" << f.tuple.src_port << "\", "
           << "\"dst\": \"" << f.tuple.dst_ip.toString() << ":" << f.tuple.dst_port << "\", "
           << "\"proto\": \"" << (f.tuple.protocol == 6 ? "TCP" : f.tuple.protocol == 17 ? "UDP" : "OTHER") << "\", "
           << "\"app\": \"" << jsonEscape(appTypeToString(f.app_type)) << "\", "
           << "\"sni\": \"" << jsonEscape(f.sni) << "\", "
           << "\"ja3\": \"" << jsonEscape(f.ja3_fingerprint) << "\", "
           << "\"packets\": " << (f.packets_in + f.packets_out) << ", "
           << "\"bytes\": " << (f.bytes_in + f.bytes_out) << ", "
           << "\"blocked\": " << (f.rule_match ? "true" : "false") << "}";
        if (i + 1 < limit) ss << ",";
        ss << "\n";
    }
    ss << "  ]\n";
    ss << "}\n";

    std::cout << ss.str();
    return true;
}

} // namespace DPI


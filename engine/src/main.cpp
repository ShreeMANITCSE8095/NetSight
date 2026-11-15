#include "engine_core.h"
#include <iostream>
#include <string>
#include <vector>

void printUsage(const char* prog) {
    std::cout << R"(
================================================================================
  NetSight Engine - Deep Packet Inspection & Real-time Flow Monitoring
================================================================================

Usage:
  netsight-engine [mode] [options]

Modes:
  --replay <file.pcap>       Stream replayed traffic in real-time over TCP
  --iface [interface]        Capture live packets from local interface (auto-selects default)
  --list-ifaces              List all available network capture interfaces
  --analyze <in> <out>       Batch offline PCAP analysis (outputs JSON to stdout)

Options:
  --port <port>              TCP port for NDJSON streaming (default: 9999)
  --host <ip>                TCP host to bind (default: 127.0.0.1)
  --rules <file>             Path to dynamic rules JSON file (default: rules.json)
  --speed <float>            Replay speed factor (1.0 = real-time, 0 = fastest)
  --no-loop                  Stop after single PCAP pass (default: loop continuously)
  --interval <ms>            Flow export interval in ms (default: 1000)
  --help, -h                 Display this help message

Examples:
  netsight-engine --replay capture.pcap --port 9999
  netsight-engine --replay capture.pcap --speed 2.0 --rules rules.json
  netsight-engine --analyze input.pcap filtered.pcap
================================================================================
)";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    DPI::EngineConfig config;

    try {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return 0;
            } else if (arg == "--list-ifaces") {
                auto devs = DPI::LiveCapture::listDevices();
                std::cout << "Available Network Capture Adapters (" << devs.size() << "):\n";
                for (size_t d = 0; d < devs.size(); ++d) {
                    std::cout << "  [" << (d + 1) << "] " << devs[d].name << "\n";
                    if (!devs[d].description.empty()) {
                        std::cout << "      " << devs[d].description << "\n";
                    }
                }
                std::string default_dev = DPI::LiveCapture::getDefaultDevice();
                std::cout << "\nDefault live adapter: " << default_dev << "\n";
                return 0;
            } else if (arg == "--replay" && i + 1 < argc) {
                config.mode = "replay";
                config.pcap_file = argv[++i];
            } else if (arg == "--iface") {
                config.mode = "live";
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    config.interface_name = argv[++i];
                }
            } else if (arg == "--analyze" && i + 2 < argc) {
                config.mode = "analyze";
                config.pcap_file = argv[++i];
                config.output_file = argv[++i];
            } else if (arg == "--port" && i + 1 < argc) {
                int p = std::stoi(argv[++i]);
                if (p >= 1 && p <= 65535) {
                    config.tcp_port = static_cast<uint16_t>(p);
                }
            } else if (arg == "--host" && i + 1 < argc) {
                config.tcp_host = argv[++i];
            } else if (arg == "--rules" && i + 1 < argc) {
                config.rules_file = argv[++i];
            } else if (arg == "--speed" && i + 1 < argc) {
                config.replay_speed = std::max<double>(0.0, std::stod(argv[++i]));
            } else if (arg == "--loop") {
                config.loop_replay = true;
            } else if (arg == "--no-loop") {
                config.loop_replay = false;
            } else if (arg == "--interval" && i + 1 < argc) {
                int interval = std::stoi(argv[++i]);
                config.export_interval_ms = static_cast<uint32_t>(std::max(100, interval));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Invalid command-line arguments: " << e.what() << "\n";
        printUsage(argv[0]);
        return 1;
    }

    DPI::EngineCore engine(config);

    if (config.mode == "analyze") {
        if (config.pcap_file.empty() || config.output_file.empty()) {
            std::cerr << "Error: --analyze requires <input.pcap> <output.pcap>\n";
            return 1;
        }
        return engine.runBatchAnalysis(config.pcap_file, config.output_file) ? 0 : 1;
    }

    std::cout << "[NetSight] Starting Engine in " << config.mode << " mode...\n";
    return engine.run() ? 0 : 1;
}


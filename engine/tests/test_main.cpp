#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include "types.h"
#include "tls_extractor.h"
#include "dns_parser.h"
#include "rule_manager.h"
#include "host_profiler.h"
#include "packet_parser.h"

using namespace DPI;

void testDomainMatching() {
    std::cout << "[Test] Running Domain Suffix & Classification tests...\n";

    // 1. Exact domains
    assert(sniToAppType("google.com") == AppType::GOOGLE);
    assert(sniToAppType("www.google.com") == AppType::GOOGLE);
    assert(sniToAppType("youtube.com") == AppType::YOUTUBE);
    assert(sniToAppType("www.youtube.com") == AppType::YOUTUBE);

    // 2. Critical bug regression tests (x.com and t.co false positives)
    // "netflix.com" contains "x.com" -> MUST be NETFLIX, NOT TWITTER!
    assert(sniToAppType("netflix.com") == AppType::NETFLIX);
    assert(sniToAppType("www.netflix.com") == AppType::NETFLIX);

    // "microsoft.com" contains "t.co" -> MUST be MICROSOFT, NOT TWITTER!
    assert(sniToAppType("microsoft.com") == AppType::MICROSOFT);
    assert(sniToAppType("www.microsoft.com") == AppType::MICROSOFT);

    // Genuine Twitter/X
    assert(sniToAppType("twitter.com") == AppType::TWITTER);
    assert(sniToAppType("x.com") == AppType::TWITTER);
    assert(sniToAppType("api.x.com") == AppType::TWITTER);
    assert(sniToAppType("t.co") == AppType::TWITTER);

    // Unrecognized domains -> default HTTPS
    assert(sniToAppType("customdomain.org") == AppType::HTTPS);

    // YouTube video chunk domain
    assert(sniToAppType("r3---sn-ab5l6n7y.googlevideo.com") == AppType::YOUTUBE);

    std::cout << "  -> Passed: Domain matching & bug regression verified.\n";
}

void testDNSEntropy() {
    std::cout << "[Test] Running DNS Query & Shannon Entropy tests...\n";

    // Normal English/domain text has lower entropy
    double normal_entropy = DNSExtractor::calculateShannonEntropy("google.com");
    // Random high-entropy string (e.g. DGA or tunneling)
    double dga_entropy = DNSExtractor::calculateShannonEntropy("x8f1q9z3m2k7w0b4p.evilcorp.com");

    assert(normal_entropy > 0.0);
    assert(dga_entropy > normal_entropy);
    assert(dga_entropy > 3.5);

    // E14 verification: Registrable label calculation avoids false positives on CDN domains
    std::string video_label = DNSExtractor::extractRegistrableLabel("r3---sn-ab5l6n7y.googlevideo.com");
    assert(video_label == "googlevideo");
    double video_entropy = DNSExtractor::calculateDomainEntropy("r3---sn-ab5l6n7y.googlevideo.com");
    assert(video_entropy < 3.5); // Safe!

    std::string dga_label = DNSExtractor::extractRegistrableLabel("x8f1q9z3m2k7w0b4p.com");
    assert(dga_label == "x8f1q9z3m2k7w0b4p");
    double dga_domain_entropy = DNSExtractor::calculateDomainEntropy("x8f1q9z3m2k7w0b4p.com");
    assert(dga_domain_entropy > 3.5); // Accurately flagged!

    std::cout << "  -> Passed: DNS entropy calculation verified (Normal: "
              << normal_entropy << ", DGA: " << dga_entropy << ").\n";
}

void testRuleManager() {
    std::cout << "[Test] Running RuleManager tests...\n";

    RuleManager rules;
    std::string json_rules = R"({
        "block_apps": ["YOUTUBE", "TIKTOK"],
        "block_domains": ["https://malware.evil.com/login", "*.phishing.net"],
        "block_ips": ["192.168.1.100", "10.0.0.0/8"],
        "block_ports": [4444]
    })";

    assert(rules.loadFromJsonString(json_rules));

    IPAddress blocked_ip = IPAddress::parse("192.168.1.100");
    IPAddress cidr_match_ip = IPAddress::parse("10.254.1.99");
    IPAddress safe_ip = IPAddress::parse("172.16.0.1");

    // Exact IP match
    auto r1 = rules.checkRule(blocked_ip, 80, AppType::HTTP, "example.com");
    assert(r1.has_value());
    assert(r1->find("Blocked IP") != std::string::npos);

    // CIDR IP match (10.0.0.0/8)
    auto r_cidr = rules.checkRule(cidr_match_ip, 80, AppType::HTTP, "example.com");
    assert(r_cidr.has_value());
    assert(r_cidr->find("10.0.0.0/8") != std::string::npos);

    // App match
    auto r2 = rules.checkRule(safe_ip, 443, AppType::YOUTUBE, "www.youtube.com");
    assert(r2.has_value());
    assert(r2->find("Blocked App") != std::string::npos);

    // Domain match with normalized input (https://... stripped)
    auto r3 = rules.checkRule(safe_ip, 443, AppType::HTTPS, "sub.malware.evil.com");
    assert(r3.has_value());
    assert(r3->find("Blocked Domain") != std::string::npos);

    // Domain match with wildcard prefix (*.phishing.net)
    auto r_wildcard = rules.checkRule(safe_ip, 443, AppType::HTTPS, "login.phishing.net");
    assert(r_wildcard.has_value());
    assert(r_wildcard->find("phishing.net") != std::string::npos);

    // Port match
    auto r_port = rules.checkRule(safe_ip, 4444, AppType::UNKNOWN, "");
    assert(r_port.has_value());
    assert(r_port->find("Blocked Port") != std::string::npos);

    // Bidirectional IP match (dst_ip blocked)
    auto r_dst_ip = rules.checkRule(safe_ip, blocked_ip, 50000, 80, AppType::HTTP, "");
    assert(r_dst_ip.has_value());
    assert(r_dst_ip->find("Blocked IP") != std::string::npos);

    // Safe traffic
    auto r4 = rules.checkRule(safe_ip, 443, AppType::GOOGLE, "www.google.com");
    assert(!r4.has_value());

    // Verify hit stats
    auto stats = rules.getStats();
    assert(stats.total_hits > 0);

    std::cout << "  -> Passed: Dynamic rule checking verified (CIDR IPs, Ports, Apps, Normalized Domains).\n";
}

void testHTTPHostExtractor() {
    std::cout << "[Test] Running HTTPHostExtractor tests...\n";

    // Standard Host header
    std::string req1 = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n";
    auto h1 = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(req1.data()), req1.size());
    assert(h1.has_value() && *h1 == "example.com");

    // Host header with port :8080 and uppercase letters
    std::string req2 = "POST /api HTTP/1.1\r\nHost: MyServer.ORG:8080\r\n\r\n";
    auto h2 = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(req2.data()), req2.size());
    assert(h2.has_value() && *h2 == "myserver.org");

    std::cout << "  -> Passed: HTTP host extraction & port stripping verified.\n";
}

void testDNSResponseParser() {
    std::cout << "[Test] Running DNS Response parsing tests...\n";

    // Build a mock DNS response packet: ID=0x1234, QR=1 (response), QDCOUNT=1, ANCOUNT=1
    // Question: example.com (0x07 example 0x03 com 0x00), Type=A (1), Class=IN (1)
    // Answer: Pointer to name (0xC0 0x0C), Type=A (1), Class=IN (1), TTL=300 (0x0000012C), RdLength=4, IP=93.184.216.34
    uint8_t dns_resp[] = {
        0x12, 0x34,             // ID
        0x81, 0x80,             // Flags: QR=1, Opcode=0, RA=1, RCODE=0
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x01,             // ANCOUNT = 1
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
        // Question
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,                   // Root
        0x00, 0x01,             // QTYPE = A
        0x00, 0x01,             // QCLASS = IN
        // Answer
        0xC0, 0x0C,             // NAME (pointer to offset 12)
        0x00, 0x01,             // TYPE = A
        0x00, 0x01,             // CLASS = IN
        0x00, 0x00, 0x01, 0x2C, // TTL = 300
        0x00, 0x04,             // RDLENGTH = 4
        93, 184, 216, 34        // IP
    };

    assert(DNSExtractor::isDNSResponse(dns_resp, sizeof(dns_resp)));
    auto parsed = DNSExtractor::extractResponse(dns_resp, sizeof(dns_resp));
    assert(parsed.has_value());
    assert(parsed->query_domain == "example.com");
    assert(!parsed->is_nxdomain);
    assert(parsed->answers.size() == 1);
    assert(parsed->answers[0].ip == "93.184.216.34");
    assert(parsed->answers[0].ttl == 300);

    std::cout << "  -> Passed: DNS response A record parsing verified.\n";
}

void testHostProfiler() {
    std::cout << "[Test] Running HostProfiler tests...\n";

    HostProfiler& prof = HostProfiler::getInstance();
    IPAddress src = IPAddress::parse("192.168.1.50");
    IPAddress dst1 = IPAddress::parse("10.0.0.1");
    IPAddress dst2 = IPAddress::parse("10.0.0.2");

    prof.recordNewConnection(src, dst1, 80, 6, 1000000ULL);
    prof.recordNewConnection(src, dst2, 443, 6, 1050000ULL);

    HostSummary s = prof.getStats(src);
    assert(s.distinct_dst_ips == 2);
    assert(s.distinct_dst_ports == 2);

    std::cout << "  -> Passed: Host profiler distinct fanout verified.\n";
}

void testTruncatedPacketParsing() {
    std::cout << "[Test] Running Truncated & Malformed Packet tests...\n";
    PacketAnalyzer::RawPacket raw;
    raw.link_type = 1; // Ethernet
    // Short 10-byte packet (smaller than 14-byte Ethernet)
    raw.data = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    PacketAnalyzer::ParsedPacket parsed;
    assert(!PacketAnalyzer::PacketParser::parse(raw, parsed));

    // Ethernet + IPv4 with invalid ihl (e.g. ihl = 2 -> 8 bytes < 20 min)
    raw.data = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00, // Eth
        0x42, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, // IPv4 with IHL=2
        10, 0, 0, 1, 10, 0, 0, 2
    };
    assert(!PacketAnalyzer::PacketParser::parse(raw, parsed));
    std::cout << "  -> Passed: Truncated & malformed headers safely rejected.\n";
}

void testDNSPointerLoop() {
    std::cout << "[Test] Running DNS Pointer Loop Resistance test...\n";
    // DNS packet where Question section points to offset 12 (0xC0 0x0C at offset 12 -> points to itself!)
    uint8_t loop_dns[] = {
        0x12, 0x34,             // ID
        0x81, 0x80,             // Flags: Response
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
        // Offset 12: compression pointer pointing to offset 12
        0xC0, 0x0C,
        0x00, 0x01,             // QTYPE = A
        0x00, 0x01              // QCLASS = IN
    };
    auto res = DNSExtractor::extractResponse(loop_dns, sizeof(loop_dns));
    assert(!res.has_value()); // Must reject cycle without hanging
    std::cout << "  -> Passed: DNS compression pointer cycle rejected safely.\n";
}

void testFragmentedTLSClientHello() {
    std::cout << "[Test] Running Fragmented / Truncated TLS ClientHello test...\n";
    // Truncated TLS record: claims length 200, only has 11 bytes
    uint8_t trunc_tls[] = {
        0x16, 0x03, 0x01, 0x00, 0xC8, // Record Header: Handshake, TLS 1.0, length 200
        0x01, 0x00, 0x00, 0xC4,       // Handshake Header: ClientHello, length 196
        0x03, 0x03                    // Version: TLS 1.2 (truncated)
    };
    auto meta = TLSExtractor::extract(trunc_tls, sizeof(trunc_tls));
    assert(!meta.has_value()); // Safely rejects truncated record
    std::cout << "  -> Passed: Truncated TLS ClientHello handled safely.\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  NetSight Engine Unit Test Suite       \n";
    std::cout << "========================================\n";

    testDomainMatching();
    testDNSEntropy();
    testRuleManager();
    testHostProfiler();
    testHTTPHostExtractor();
    testDNSResponseParser();
    testTruncatedPacketParsing();
    testDNSPointerLoop();
    testFragmentedTLSClientHello();

    std::cout << "========================================\n";
    std::cout << "  All Engine Unit Tests PASSED!         \n";
    std::cout << "========================================\n";
    return 0;
}


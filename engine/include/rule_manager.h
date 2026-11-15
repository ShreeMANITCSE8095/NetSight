#ifndef NETSIGHT_RULE_MANAGER_H
#define NETSIGHT_RULE_MANAGER_H

#include "types.h"
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <shared_mutex>
#include <mutex>
#include <optional>
#include <chrono>

namespace DPI {

struct IPCidrRule {
    uint8_t family = 4;
    std::array<uint8_t, 16> bytes{};
    uint8_t prefix_len = 32;
    std::string text;

    bool matches(const IPAddress& ip) const;
};

class RuleManager {
public:
    RuleManager() = default;

    // Rule mutation
    void blockIP(const std::string& ip_or_cidr);
    void unblockIP(const std::string& ip_or_cidr);
    bool isIPBlocked(const IPAddress& ip) const;

    void blockApp(AppType app);
    void unblockApp(AppType app);
    bool isAppBlocked(AppType app) const;

    void blockDomain(const std::string& domain);
    void unblockDomain(const std::string& domain);
    bool isDomainBlocked(const std::string& domain) const;

    void blockPort(uint16_t port);
    void unblockPort(uint16_t port);
    bool isPortBlocked(uint16_t port) const;

    // Combined rule check: returns reason string if matched, nullopt otherwise.
    std::optional<std::string> checkRule(
        const IPAddress& src_ip,
        const IPAddress& dst_ip,
        uint16_t src_port,
        uint16_t dst_port,
        AppType app,
        const std::string& domain);

    std::optional<std::string> checkRule(
        const IPAddress& src_ip,
        uint16_t dst_port,
        AppType app,
        const std::string& domain);

    // Monotonic rules version (increments on any rule change)
    uint32_t getVersion() const;

    // File loading and dynamic polling
    bool loadFromFile(const std::string& filename);
    bool loadFromJsonString(const std::string& json_str);
    bool pollFileChanges(const std::string& filename);
    void clear();

    struct RuleStats {
        size_t blocked_ips = 0;
        size_t blocked_apps = 0;
        size_t blocked_domains = 0;
        size_t blocked_ports = 0;
        uint64_t total_hits = 0;
    };
    RuleStats getStats() const;

    std::vector<std::string> getBlockedIPs() const;
    std::vector<std::string> getBlockedApps() const;
    std::vector<std::string> getBlockedDomains() const;
    std::vector<uint16_t> getBlockedPorts() const;
    std::unordered_map<std::string, uint64_t> getHitCounts() const;

    static std::string normalizeDomain(const std::string& domain);

private:
    mutable std::shared_mutex mutex_;
    mutable std::mutex hits_mutex_;
    std::vector<IPCidrRule> cidr_rules_;
    std::unordered_set<std::string> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
    std::unordered_set<uint16_t> blocked_ports_;
    std::unordered_map<std::string, uint64_t> rule_hit_counts_;

    uint32_t rules_version_ = 1;
    bool rules_loaded_ = false;
    int64_t last_mod_ticks_ = 0;
    uintmax_t last_file_size_ = 0;
};

} // namespace DPI

#endif // NETSIGHT_RULE_MANAGER_H

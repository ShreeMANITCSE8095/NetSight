#include "rule_manager.h"
#include "platform.h"
#include <mutex>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <cstring>

namespace DPI {

bool IPCidrRule::matches(const IPAddress& ip) const {
    if (ip.family != family) return false;
    if (family == 4) {
        uint32_t net_a = PortableNet::readBE32(ip.bytes.data());
        uint32_t net_b = PortableNet::readBE32(bytes.data());
        uint32_t mask = (prefix_len == 0) ? 0 : (~0U << (32 - prefix_len));
        return (net_a & mask) == (net_b & mask);
    } else {
        int full_bytes = prefix_len / 8;
        int rem_bits = prefix_len % 8;
        if (full_bytes > 0 && std::memcmp(ip.bytes.data(), bytes.data(), full_bytes) != 0) return false;
        if (rem_bits > 0) {
            uint8_t mask = static_cast<uint8_t>(~0U << (8 - rem_bits));
            if ((ip.bytes[full_bytes] & mask) != (bytes[full_bytes] & mask)) return false;
        }
        return true;
    }
}

static std::optional<IPCidrRule> parseIpOrCidr(const std::string& input) {
    std::string s = input;
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    if (s.empty()) return std::nullopt;

    size_t slash = s.find('/');
    std::string ip_part = (slash != std::string::npos) ? s.substr(0, slash) : s;
    std::string cidr_part = (slash != std::string::npos) ? s.substr(slash + 1) : "";

    IPAddress parsed = IPAddress::parse(ip_part);
    if (parsed.family == 0) return std::nullopt;

    uint8_t prefix = (parsed.family == 6) ? 128 : 32;
    if (!cidr_part.empty()) {
        try {
            int p = std::stoi(cidr_part);
            if (p < 0 || (parsed.family == 4 && p > 32) || (parsed.family == 6 && p > 128)) {
                return std::nullopt;
            }
            prefix = static_cast<uint8_t>(p);
        } catch (...) {
            return std::nullopt;
        }
    }

    IPCidrRule rule;
    rule.family = parsed.family;
    rule.bytes = parsed.bytes;
    rule.prefix_len = prefix;
    rule.text = s;
    return rule;
}

std::string RuleManager::normalizeDomain(const std::string& domain) {
    std::string d = domain;
    while (!d.empty() && (d.front() == ' ' || d.front() == '\t')) d.erase(d.begin());
    while (!d.empty() && (d.back() == ' ' || d.back() == '\t')) d.pop_back();
    if (d.rfind("http://", 0) == 0) d = d.substr(7);
    else if (d.rfind("https://", 0) == 0) d = d.substr(8);
    size_t slash = d.find('/');
    if (slash != std::string::npos) d = d.substr(0, slash);
    size_t colon = d.find(':');
    if (colon != std::string::npos) d = d.substr(0, colon);
    if (d.rfind("*.", 0) == 0) d = d.substr(2);
    std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!d.empty() && d.back() == '.') d.pop_back();
    return d;
}

void RuleManager::blockIP(const std::string& ip_or_cidr) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto r = parseIpOrCidr(ip_or_cidr);
    if (r) {
        cidr_rules_.push_back(*r);
        blocked_ips_.insert(r->text);
        rules_version_++;
    }
}

void RuleManager::unblockIP(const std::string& ip_or_cidr) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    blocked_ips_.erase(ip_or_cidr);
    cidr_rules_.erase(
        std::remove_if(cidr_rules_.begin(), cidr_rules_.end(),
                       [&](const IPCidrRule& r) { return r.text == ip_or_cidr; }),
        cidr_rules_.end()
    );
    rules_version_++;
}

bool RuleManager::isIPBlocked(const IPAddress& ip) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& r : cidr_rules_) {
        if (r.matches(ip)) return true;
    }
    return false;
}

void RuleManager::blockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    blocked_apps_.insert(app);
    rules_version_++;
}

void RuleManager::unblockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    blocked_apps_.erase(app);
    rules_version_++;
}

bool RuleManager::isAppBlocked(AppType app) const {
    if (app == AppType::UNKNOWN) return false;
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return blocked_apps_.count(app) > 0;
}

void RuleManager::blockDomain(const std::string& domain) {
    std::string d = normalizeDomain(domain);
    if (d.empty()) return;
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (std::find(blocked_domains_.begin(), blocked_domains_.end(), d) == blocked_domains_.end()) {
        blocked_domains_.push_back(d);
        rules_version_++;
    }
}

void RuleManager::unblockDomain(const std::string& domain) {
    std::string d = normalizeDomain(domain);
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = std::remove(blocked_domains_.begin(), blocked_domains_.end(), d);
    if (it != blocked_domains_.end()) {
        blocked_domains_.erase(it, blocked_domains_.end());
        rules_version_++;
    }
}

static bool domainMatchesPattern(const std::string& host, const std::string& pattern) {
    if (host.size() < pattern.size()) return false;
    if (host.compare(host.size() - pattern.size(), pattern.size(), pattern) != 0) return false;
    return host.size() == pattern.size() || host[host.size() - pattern.size() - 1] == '.';
}

bool RuleManager::isDomainBlocked(const std::string& domain) const {
    if (domain.empty()) return false;
    std::string d = normalizeDomain(domain);

    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& pattern : blocked_domains_) {
        if (domainMatchesPattern(d, pattern)) {
            return true;
        }
    }
    return false;
}

void RuleManager::blockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    blocked_ports_.insert(port);
    rules_version_++;
}

void RuleManager::unblockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    blocked_ports_.erase(port);
    rules_version_++;
}

bool RuleManager::isPortBlocked(uint16_t port) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return blocked_ports_.count(port) > 0;
}

uint32_t RuleManager::getVersion() const {
    return rules_version_;
}

std::optional<std::string> RuleManager::checkRule(
    const IPAddress& src_ip,
    const IPAddress& dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    AppType app,
    const std::string& domain) {

    std::shared_lock<std::shared_mutex> lock(mutex_);

    // 1. IP checks (bidirectional CIDR and exact IP)
    for (const auto& r : cidr_rules_) {
        if (r.matches(src_ip) || (dst_ip.family != 0 && r.matches(dst_ip))) {
            std::string reason = "Blocked IP: " + r.text;
            {
                std::lock_guard<std::mutex> hlock(hits_mutex_);
                rule_hit_counts_[reason]++;
            }
            return reason;
        }
    }

    // 2. Port checks (bidirectional)
    if ((dst_port != 0 && blocked_ports_.count(dst_port)) ||
        (src_port != 0 && blocked_ports_.count(src_port))) {
        uint16_t matched_port = (dst_port != 0 && blocked_ports_.count(dst_port)) ? dst_port : src_port;
        std::string reason = "Blocked Port: " + std::to_string(matched_port);
        {
            std::lock_guard<std::mutex> hlock(hits_mutex_);
            rule_hit_counts_[reason]++;
        }
        return reason;
    }

    // 3. Application check
    if (app != AppType::UNKNOWN && blocked_apps_.count(app)) {
        std::string reason = "Blocked App: " + appTypeToString(app);
        {
            std::lock_guard<std::mutex> hlock(hits_mutex_);
            rule_hit_counts_[reason]++;
        }
        return reason;
    }

    // 4. Domain suffix boundary check
    if (!domain.empty()) {
        std::string d = normalizeDomain(domain);
        for (const auto& pattern : blocked_domains_) {
            if (domainMatchesPattern(d, pattern)) {
                std::string reason = "Blocked Domain: " + pattern;
                {
                    std::lock_guard<std::mutex> hlock(hits_mutex_);
                    rule_hit_counts_[reason]++;
                }
                return reason;
            }
        }
    }

    return std::nullopt;
}

std::optional<std::string> RuleManager::checkRule(
    const IPAddress& src_ip,
    uint16_t dst_port,
    AppType app,
    const std::string& domain) {
    return checkRule(src_ip, IPAddress{}, 0, dst_port, app, domain);
}

void RuleManager::clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    cidr_rules_.clear();
    blocked_ips_.clear();
    blocked_apps_.clear();
    blocked_domains_.clear();
    blocked_ports_.clear();
    rules_version_++;
}

RuleManager::RuleStats RuleManager::getStats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    uint64_t hits = 0;
    {
        std::lock_guard<std::mutex> hlock(hits_mutex_);
        for (const auto& pair : rule_hit_counts_) hits += pair.second;
    }
    return {
        cidr_rules_.size(),
        blocked_apps_.size(),
        blocked_domains_.size(),
        blocked_ports_.size(),
        hits
    };
}

std::vector<std::string> RuleManager::getBlockedIPs() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return std::vector<std::string>(blocked_ips_.begin(), blocked_ips_.end());
}

std::vector<std::string> RuleManager::getBlockedApps() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> out;
    for (auto app : blocked_apps_) {
        out.push_back(appTypeToString(app));
    }
    return out;
}

std::vector<std::string> RuleManager::getBlockedDomains() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return blocked_domains_;
}

std::vector<uint16_t> RuleManager::getBlockedPorts() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return std::vector<uint16_t>(blocked_ports_.begin(), blocked_ports_.end());
}

std::unordered_map<std::string, uint64_t> RuleManager::getHitCounts() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::lock_guard<std::mutex> hlock(hits_mutex_);
    return rule_hit_counts_;
}

static std::vector<std::string> parseJsonStringArray(const std::string& json, const std::string& key) {
    std::vector<std::string> items;
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return items;

    size_t open_bracket = json.find('[', pos);
    if (open_bracket == std::string::npos) return items;

    size_t close_bracket = json.find(']', open_bracket);
    if (close_bracket == std::string::npos) return items;

    std::string array_body = json.substr(open_bracket + 1, close_bracket - open_bracket - 1);
    size_t i = 0;
    while (i < array_body.size()) {
        size_t quote_start = array_body.find('"', i);
        if (quote_start == std::string::npos) break;
        size_t quote_end = array_body.find('"', quote_start + 1);
        if (quote_end == std::string::npos) break;

        items.push_back(array_body.substr(quote_start + 1, quote_end - quote_start - 1));
        i = quote_end + 1;
    }
    return items;
}

static std::vector<uint16_t> parseJsonIntArray(const std::string& json, const std::string& key) {
    std::vector<uint16_t> items;
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return items;

    size_t open_bracket = json.find('[', pos);
    if (open_bracket == std::string::npos) return items;

    size_t close_bracket = json.find(']', open_bracket);
    if (close_bracket == std::string::npos) return items;

    std::string body = json.substr(open_bracket + 1, close_bracket - open_bracket - 1);
    std::stringstream ss(body);
    std::string token;
    while (std::getline(ss, token, ',')) {
        try {
            int val = std::stoi(token);
            if (val >= 1 && val <= 65535) {
                items.push_back(static_cast<uint16_t>(val));
            }
        } catch (...) {}
    }
    return items;
}

bool RuleManager::loadFromJsonString(const std::string& json_str) {
    auto apps = parseJsonStringArray(json_str, "block_apps");
    auto domains = parseJsonStringArray(json_str, "block_domains");
    auto ips = parseJsonStringArray(json_str, "block_ips");
    auto ports = parseJsonIntArray(json_str, "block_ports");

    clear();
    for (const auto& a : apps) {
        AppType t = stringToAppType(a);
        if (t != AppType::UNKNOWN) blockApp(t);
    }
    for (const auto& d : domains) {
        blockDomain(d);
    }
    for (const auto& ip : ips) {
        blockIP(ip);
    }
    for (uint16_t p : ports) {
        blockPort(p);
    }
    return true;
}

bool RuleManager::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // Check if JSON format
    if (content.find('{') != std::string::npos && content.find('}') != std::string::npos) {
        return loadFromJsonString(content);
    }

    // Legacy INI / Section format fallback
    clear();
    std::istringstream stream(content);
    std::string line;
    std::string section;
    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == '#') continue;
        if (line[0] == '[') {
            section = line;
            continue;
        }
        if (section == "[BLOCKED_IPS]") blockIP(line);
        else if (section == "[BLOCKED_APPS]") {
            AppType t = stringToAppType(line);
            if (t != AppType::UNKNOWN) blockApp(t);
        }
        else if (section == "[BLOCKED_DOMAINS]") blockDomain(line);
        else if (section == "[BLOCKED_PORTS]") {
            try { blockPort(static_cast<uint16_t>(std::stoi(line))); } catch (...) {}
        }
    }
    return true;
}

bool RuleManager::pollFileChanges(const std::string& filename) {
    try {
        if (!std::filesystem::exists(filename)) {
            if (rules_loaded_) {
                clear();
                rules_loaded_ = false;
                return true;
            }
            return false;
        }
        auto ftime = std::filesystem::last_write_time(filename);
        auto fsize = std::filesystem::file_size(filename);
        auto ticks = ftime.time_since_epoch().count();

        if (ticks != last_mod_ticks_ || fsize != last_file_size_) {
            last_mod_ticks_ = ticks;
            last_file_size_ = fsize;
            rules_loaded_ = true;
            return loadFromFile(filename);
        }
    } catch (...) {
        return false;
    }
    return false;
}

} // namespace DPI

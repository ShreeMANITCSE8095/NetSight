#include "types.h"
#include "platform.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace DPI {

IPAddress IPAddress::parse(const std::string& str) {
    IPAddress addr;
    if (str.find(':') != std::string::npos) {
        addr.family = 6;
        if (inet_pton(AF_INET6, str.c_str(), addr.bytes.data()) != 1) {
            addr.bytes.fill(0);
        }
    } else {
        addr.family = 4;
        if (inet_pton(AF_INET, str.c_str(), addr.bytes.data()) != 1) {
            addr.bytes.fill(0);
        }
    }
    return addr;
}

std::string IPAddress::toString() const {
    char buf[64];
    if (family == 4) {
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
        return buf;
    }

    uint16_t g[8];
    for (int i = 0; i < 8; ++i) {
        g[i] = static_cast<uint16_t>((bytes[2 * i] << 8) | bytes[2 * i + 1]);
    }
    // Longest run of zero groups (length >= 2) becomes "::" (RFC 5952).
    int best_start = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (g[i] == 0) {
            int j = i;
            while (j < 8 && g[j] == 0) ++j;
            if (j - i > best_len) { best_len = j - i; best_start = i; }
            i = j;
        } else {
            ++i;
        }
    }
    if (best_len < 2) best_start = -1;

    std::string out;
    for (int i = 0; i < 8;) {
        if (i == best_start) {
            out += "::";
            i += best_len;
            continue;
        }
        if (!out.empty() && out.back() != ':') out += ':';
        std::snprintf(buf, sizeof(buf), "%x", g[i]);
        out += buf;
        ++i;
    }
    return out;
}

std::string FiveTuple::toString() const {
    const char* proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP"
                      : protocol == 1 ? "ICMP" : protocol == 58 ? "ICMPv6" : "?";
    std::string s;
    if (src_ip.isV6()) {
        s = "[" + src_ip.toString() + "]:" + std::to_string(src_port) + " -> [" +
            dst_ip.toString() + "]:" + std::to_string(dst_port);
    } else {
        s = src_ip.toString() + ":" + std::to_string(src_port) + " -> " +
            dst_ip.toString() + ":" + std::to_string(dst_port);
    }
    return s + " (" + proto + ")";
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

AppType stringToAppType(const std::string& str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); ++i) {
        AppType t = static_cast<AppType>(i);
        std::string name = appTypeToString(t);
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::toupper(c); });
        if (s == name || (t == AppType::TWITTER && s == "TWITTER")) {
            return t;
        }
    }
    return AppType::UNKNOWN;
}

namespace {

struct DomainRule {
    const char* suffix;
    AppType app;
};

// Domain rules match strictly when the hostname equals the suffix OR ends with "." + suffix.
// This prevents substring false positives (e.g. netflix.com matching x.com or microsoft.com matching t.co).
const DomainRule kRules[] = {
    {"google.com", AppType::GOOGLE},       {"google.co.in", AppType::GOOGLE},
    {"googleapis.com", AppType::GOOGLE},   {"gstatic.com", AppType::GOOGLE},
    {"ggpht.com", AppType::GOOGLE},        {"gvt1.com", AppType::GOOGLE},
    {"googleusercontent.com", AppType::GOOGLE},
    {"youtube.com", AppType::YOUTUBE},     {"ytimg.com", AppType::YOUTUBE},
    {"youtu.be", AppType::YOUTUBE},        {"youtube-nocookie.com", AppType::YOUTUBE},
    {"googlevideo.com", AppType::YOUTUBE},
    {"facebook.com", AppType::FACEBOOK},   {"facebook.net", AppType::FACEBOOK},
    {"fbcdn.net", AppType::FACEBOOK},      {"fb.com", AppType::FACEBOOK},
    {"fbsbx.com", AppType::FACEBOOK},      {"meta.com", AppType::FACEBOOK},
    {"instagram.com", AppType::INSTAGRAM}, {"cdninstagram.com", AppType::INSTAGRAM},
    {"whatsapp.com", AppType::WHATSAPP},   {"whatsapp.net", AppType::WHATSAPP},
    {"wa.me", AppType::WHATSAPP},
    {"twitter.com", AppType::TWITTER},     {"twimg.com", AppType::TWITTER},
    {"x.com", AppType::TWITTER},           {"t.co", AppType::TWITTER},
    {"netflix.com", AppType::NETFLIX},     {"nflxvideo.net", AppType::NETFLIX},
    {"nflximg.net", AppType::NETFLIX},     {"nflxso.net", AppType::NETFLIX},
    {"amazon.com", AppType::AMAZON},       {"amazon.in", AppType::AMAZON},
    {"amazonaws.com", AppType::AMAZON},    {"cloudfront.net", AppType::AMAZON},
    {"amazon-adsystem.com", AppType::AMAZON},
    {"microsoft.com", AppType::MICROSOFT}, {"msn.com", AppType::MICROSOFT},
    {"office.com", AppType::MICROSOFT},    {"office365.com", AppType::MICROSOFT},
    {"azure.com", AppType::MICROSOFT},     {"azureedge.net", AppType::MICROSOFT},
    {"live.com", AppType::MICROSOFT},      {"outlook.com", AppType::MICROSOFT},
    {"bing.com", AppType::MICROSOFT},      {"windows.net", AppType::MICROSOFT},
    {"microsoftonline.com", AppType::MICROSOFT},
    {"apple.com", AppType::APPLE},         {"icloud.com", AppType::APPLE},
    {"mzstatic.com", AppType::APPLE},      {"itunes.com", AppType::APPLE},
    {"telegram.org", AppType::TELEGRAM},   {"telegram.me", AppType::TELEGRAM},
    {"t.me", AppType::TELEGRAM},
    {"tiktok.com", AppType::TIKTOK},       {"tiktokcdn.com", AppType::TIKTOK},
    {"musical.ly", AppType::TIKTOK},       {"bytedance.com", AppType::TIKTOK},
    {"byteoversea.com", AppType::TIKTOK},
    {"spotify.com", AppType::SPOTIFY},     {"scdn.co", AppType::SPOTIFY},
    {"zoom.us", AppType::ZOOM},            {"zoom.com", AppType::ZOOM},
    {"discord.com", AppType::DISCORD},     {"discordapp.com", AppType::DISCORD},
    {"discord.gg", AppType::DISCORD},
    {"github.com", AppType::GITHUB},       {"githubusercontent.com", AppType::GITHUB},
    {"github.io", AppType::GITHUB},
    {"cloudflare.com", AppType::CLOUDFLARE}, {"cloudflare-dns.com", AppType::CLOUDFLARE},
    {"cloudflarestream.com", AppType::CLOUDFLARE},
};

bool hasDomainSuffix(const std::string& host, const char* suffix) {
    const size_t n = std::char_traits<char>::length(suffix);
    if (host.size() < n) return false;
    if (host.compare(host.size() - n, n, suffix) != 0) return false;
    return host.size() == n || host[host.size() - n - 1] == '.';
}

} // namespace

AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;

    std::string host = sni;
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!host.empty() && host.back() == '.') host.pop_back();

    for (const auto& rule : kRules) {
        if (hasDomainSuffix(host, rule.suffix)) return rule.app;
    }
    // SNI present but not recognized: still TLS/HTTPS.
    return AppType::HTTPS;
}

} // namespace DPI

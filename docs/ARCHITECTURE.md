# NetSight Architecture & Design Specification

## 1. System Overview

```
 [Network Interface (Live)] OR [PCAP File (Replay)]
                       │
                       ▼
            ┌──────────────────────┐
            │     NetSight C++     │
            │      DPI Engine      │
            └──────────┬───────────┘
                       │ NDJSON over TCP (127.0.0.1:9999)
                       ▼
            ┌──────────────────────┐   Dynamic Rules
            │   Python Collector   │ ───────────────► rules.json
            │  (FastAPI + asyncio) │ ◄─────────────── (file poll 1s)
            └─────┬──────────┬─────┘
                  │          │
         REST API │          │ WebSocket (/ws/live)
                  ▼          ▼
            ┌──────────────────────┐
            │   React Dashboard    │ (Direct on :8000 or Vite :5173)
            │ (TypeScript + Vite)  │ (Auralis Design System)
            └──────────────────────┘
```

NetSight is an end-to-end network traffic inspection and flow telemetry platform that identifies application protocols and domain names from encrypted network traffic without breaking TLS encryption.

---

## 2. Core Engine Architecture (`engine/`)

### 2.1 Unified Entry Point
Instead of separate binaries, NetSight uses a single, robust entry point (`netsight-engine`):
- `netsight-engine --replay capture.pcap --port 9999 [--speed 10] [--loop]`
- `netsight-engine --iface \Device\NPF_... --port 9999`
- `netsight-engine --analyze input.pcap output.pcap [--rules rules.json]`

All modes feed an identical, hardened core pipeline:
1. **Packet Ingestion**: `PcapReader` supports classic `.pcap` and `.pcapng` with microsecond/nanosecond timestamps and endianness byte-swapping.
2. **Bounds-Checked Parser**: `PacketParser` validates variable-length IPv4 headers (`ihl >= 5`) and TCP offsets (`data_offset >= 5`) against captured packet length (`caplen`), parsing Ethernet, 802.1Q VLAN tags, IPv4, IPv6, TCP, UDP, and ICMP without reading past buffer boundaries.
3. **O(1) Bidirectional Flow Table**: `ConnectionTracker` maintains an LRU-indexed hash table where forward packets and reverse replies map to the same canonical bidirectional `Connection`.
4. **Deep Packet Inspection**:
   - **TLS Handshake Parsing**: `TLSExtractor` inspects Client Hello records, checks remaining buffer bounds (`c.remaining() < ext_len`), eliminates GREASE suites, extracts SNI domains, and computes JA3 client fingerprint strings and MD5 hashes. Includes TCP sequence number tracking (`tls_next_seq`) to prevent buffer corruption from out-of-order or duplicate packets.
   - **Domain Boundary Suffix Matcher**: `sniToAppType()` uses exact suffix domain boundary matching (`.netflix.com` vs `.x.com`) preventing substring misclassifications.
   - **DNS Telemetry**: `DNSExtractor` extracts queries and responses with bounded loop limits (`qdcount <= 10`, `ancount <= 100`), enforces strictly decreasing jump offsets (`max_jumps = 16`, `ptr < curr && ptr < last_ptr`) to prevent compression pointer loops, calculates Shannon entropy ($H$ in bits/char) to flag DGA or tunneling, and records record types (A, AAAA, TXT).
   - **HTTP Host**: `HTTPHostExtractor` extracts Host headers from unencrypted HTTP/1.1 traffic.
5. **Host Profiling**: `HostProfiler` tracks fan-out (`distinct_dst_ips`, `distinct_dst_ports`) per host with bounded memory tables (`kMaxPortsPerHost = 256`, `kMaxDistinctPerHost = 256`, 100,000 entries total) to expose horizontal and vertical port scanners under spoofed traffic.
6. **Dynamic Rule Checking**: `RuleManager` checks IP/CIDR, Port, App, and Domain rules using read-write locks (`std::shared_mutex`) and automatically reloads on `rules.json` file modifications.
7. **NDJSON TCP Streaming**: `TcpServer` broadcasts single-line JSON records to connected collectors over `127.0.0.1:9999` using a bounded 10,000-message queue with drop-oldest policy and a dedicated sender thread.

---

## 3. Python Collector Architecture (`collector/`)

- Built with **Python 3.11+**, **FastAPI**, and **asyncio**.
- Ingests the TCP NDJSON stream from the C++ engine over `127.0.0.1:9999` with a defensive 1 MB line-size cap and robust `LimitOverrunError` / `JSONDecodeError` handling.
- **In-Memory Active Cache**: `FlowCache` retains flow states, computes server-side pagination (`offset`, `order`), atomic dictionary swaps under lock, and evaluates quick filters (`flagged`, `unlabeled`, `upload_heavy`).
- **SQLite Database**: `Database` persists historical traffic as 1-minute bucketed rollups in WAL mode (`history_minute`, `history_app`, `history_domain`) with `PRAGMA busy_timeout = 5000;` and automated 7-day retention cleanup (`prune_history`).
- **Security & Hardening**:
  - Optional `NETSIGHT_API_KEY` authentication on sensitive REST routes and WebSocket handshakes (`X-API-Key` or `Bearer` token).
  - Cross-Site WebSocket Hijacking (CSWSH) protection validating `Origin` against `CORS_ORIGINS`.
  - Max client cap (16) and bounded receive frame sizes on WebSocket.
  - Concurrency-limited PCAP batch analysis (`asyncio.Semaphore(1)`) with streaming chunked file upload (100 MB cap) and 36-character UUIDv4 download tokens.
- **Dual Dashboard Serving**: Directly mounts `dashboard/dist` static assets at `/` so the dashboard is instantly accessible on `http://127.0.0.1:8000/` without needing Node.js or Vite at runtime.

---

## 4. Frontend Architecture (`dashboard/`)

- Built with **React 18**, **TypeScript**, and **Vite**, adhering to the **Auralis Design System**:
  - **Surface Tokens**: Warm stone light theme (`#f5f5f4` canvas, `#ffffff` card surface, `#ececeb` sidebar, `#e5e5e0` border) and matte obsidian dark theme (`#121211` canvas, `#1b1b19` surface, `#161615` sidebar, `#2a2a27` border).
  - **Typography**: Google Inter for UI prose and JetBrains Mono for monospace IPs, ports, and timestamps.
  - **Collapsible Left Sidebar**: Compact `w-14` icon rail expanding to `w-60` with Brand infinity glyph and navigation.
  - **Slim 48px Top Header Bar**: Sidebar toggle, active view title, contextual History range dropdown with calendar timestamps, live engine status dot, and Light / Dark / System theme switcher.
  - **Dynamic Unit Scaling**: Telemetry rates dynamically scale from bps $\rightarrow$ Kbps $\rightarrow$ Mbps $\rightarrow$ Gbps, eliminating zero-rounding floor bugs on light traffic.
  - **Math Stability**: Rolling 5-second exponential moving averages ($\alpha=0.33$) prevent NaN% or $\infty$% spikes.
- **Views**:
  1. **Overview**: Exact 3-row layout:
     - *Row 1*: 4 KPI Cards (Live Bandwidth, Packets/Sec, Avg. Packet Size, Active Connections) with emerald/rose % delta badges.
     - *Row 2*: Bandwidth History AreaChart (col-span-8) with `isAnimationActive={false}` + Protocol Distribution Donut (col-span-4).
     - *Row 3*: 3 Horizontal Bar Cards (Top Talkers, Top Destinations, Top Services) with vertical axis dividers, outside byte counters, and hover tooltips.
  2. **Connections (Flows)**: Full-bleed minimalist 7-column sortable table with quick filter chips (All, Flagged, Unlabeled, Upload-Heavy), search filter, sort toggling, hover-to-pause live updates, and a slide-over deep flow inspector drawer detailing JA3 MD5/raw string, byte ratio asymmetry, TCP flags, DNS Shannon entropy, and host fan-out.
  3. **History**: Contextual time-range preset picker (1h, 6h, 24h, 7d, 30d) with AbortController, animated infinity loader, historical throughput AreaChart, wrapped Top 5 + Other Protocol Donut, and 3 Horizontal Bar Cards.
  4. **DPI Analytics**: Deep DPI summary cards, Top Applications and Domains, JA3 Client Fingerprints table, DNS Shannon Entropy and Host Reconnaissance Fan-Out table, and Real-Time Security Findings with dismiss/acknowledge actions.
  5. **Analyze PCAP**: Drag-and-drop offline capture uploader with input reset, capture KPIs, file size, unique flows, top talkers, top apps, and top domains inspection cards.
  6. **Firewall Rules**: Blocked IPs, Domains, Transport Ports, and Applications manager with instant rule deletion and validation alerts.
  7. **About NetSight**: Narrative and architectural feature breakdown with author credits.

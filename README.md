# NetSight

NetSight is a high-speed C++17 DPI engine and real-time network telemetry platform (1.02M+ pps) with zero-decryption L7 classification, FastAPI, and React.

Most network traffic is TLS-encrypted on port 443. Standard port-based dashboards cannot distinguish between high-bandwidth video streaming, cloud backups, and malicious command-and-control beacons. NetSight inspects unencrypted TLS Client Hello handshakes, HTTP Host headers, and DNS queries in real-time, mapping traffic to applications and domains without decrypting packet payloads.

---

## Architecture Overview

```
 network interface (or PCAP replay)
            │
   [C++ Engine]         Parse Ethernet/IP/TCP/UDP/ICMP, O(1) flow tracking, SNI, JA3, DNS entropy, rules check
            │           Newline-delimited JSON (NDJSON) over local TCP socket (127.0.0.1:9999)
   [Python Collector]   FastAPI + asyncio: ingest, in-memory aggregation, SQLite rollups, REST & WebSocket
            │           REST & WebSocket (/ws/live)
   [React Dashboard]    Auralis Design System UI in React 18 + TypeScript + Vite + Tailwind CSS (:8000 / :5173)
```

---

## Key Capabilities

1. **Application & Domain Classification**: Identifies 20+ protocols and platforms (Google, YouTube, Facebook, Microsoft, Netflix, Amazon, Apple, Instagram, WhatsApp, Telegram, Spotify, Zoom, Discord, GitHub, etc.) using domain boundary suffix matching.
2. **Deep Flow Analytics**:
   - **Directional Volume & Asymmetry**: Measures `bytes_in`, `bytes_out`, and `byte_ratio` ($bytes_{out} / bytes_{in}$) to flag unusual uploads or data exfiltration.
   - **TCP Connection Health**: Tracks `SYN`, `SYN-ACK`, `FIN`, and `RST` flag counts per flow to reveal connection drops and half-open port scans.
   - **JA3 Client Fingerprints & Hashes**: Extracts the TLS Client Hello cipher suite and extension parameters to compute MD5 JA3 hashes, identifying client runtimes even if SNI is omitted or obscured.
   - **DNS Shannon Entropy**: Computes character entropy on DNS queries to identify Domain Generation Algorithms (DGA) and DNS tunneling ($H > 3.8$ bits/char).
   - **Host Fanout Profiling**: Tracks distinct destination IPs and ports per host to pinpoint active network scanners.
3. **Auralis Design System UI**:
   - Warm stone light theme (`#f5f5f4`) and matte obsidian dark theme (`#121211`) with clean 1px borders.
   - Collapsible left sidebar (`w-14` $\leftrightarrow$ `w-60` icon rail) and slim 48px header with Light/Dark/System theme switcher.
   - 3-row Overview layout (Row 1: 4 KPI Cards; Row 2: Bandwidth History AreaChart + Protocol Donut; Row 3: 3 Horizontal Bar Cards).
   - Full-bleed minimalist 7-column sortable Connections table with hover-to-pause live updates.
   - History view with animated infinity loader and range picker (1h, 6h, 24h, 7d, 30d).
   - Dedicated DPI Analytics and offline PCAP uploader.
4. **Dynamic Rule Checking**: Rule changes in the UI write to `rules.json`. The C++ engine polls file modification times and reloads rules in memory via read-write locks (`std::shared_mutex`).
5. **Unified Single Entry Point**: A single C++ binary handles PCAP replay (`--replay`), live network capture (`--iface`), and offline batch analysis (`--analyze`).

---

## Quickstart (Windows Native Demo)

### One-Command Launcher
Run PowerShell from the repository root:
```powershell
.\run_demo.ps1
```
Or double-click `run_demo.bat`.

This automatically:
1. Verifies/builds the compiled C++ engine (`engine\build\Release\netsight-engine.exe`).
2. Starts the engine replaying sample PCAP traffic on port `9999` (or live capture if selected).
3. Starts the Python Collector on `http://127.0.0.1:8000`.
4. Serves the React Dashboard natively on `http://127.0.0.1:8000` (via FastAPI static mount) and launches Vite preview on `http://localhost:5173` if Node/Vite is installed.
5. Opens your default web browser to the dashboard.

---

## Manual Execution Steps

### 1. Build the C++ Engine
Requirements: Visual Studio 2022/2026 (MSVC C++17) or GCC 11+ on Linux, and CMake 3.16+.

```powershell
cd engine
cmake -B build
cmake --build build --config Release
```

Run C++ unit tests:
```powershell
.\build\Release\engine-tests.exe
```

### 2. Start the Python Collector
Requirements: Python 3.11+.

```powershell
# Install runtime dependencies
pip install -r collector/requirements.txt

# Or install test/dev dependencies
pip install -r collector/requirements-dev.txt

# Run the FastAPI server
python -m uvicorn collector.main:app --host 127.0.0.1 --port 8000
```

Run Collector unit & integration tests:
```powershell
python -m pytest collector/tests/ -v
```

### 3. Build & Run the React Dashboard
Requirements: Node.js 18+ and npm.

```powershell
cd dashboard
npm install
npm run build
npm run preview
```

---

## Docker Compose (Linux / Production Deployment)

Run the entire pipeline in containerized micro-services:

```bash
docker compose up --build
```

- **Dashboard**: `http://localhost:3000` (Nginx) or `http://localhost:8000` (Collector)
- **REST API**: `http://localhost:8000/api/summary`
- **WebSocket Feed**: `ws://localhost:8000/ws/live`
- **Engine Stream**: port `9999` (bound to `127.0.0.1`)

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Collector uptime, engine connectivity status, active flow count. |
| `GET` | `/api/summary` | Telemetry KPIs: instant bps, pps, active flows, top app, top domain, drops. |
| `GET` | `/api/rates` | Time series array of 1-second rate samples (`?seconds=900`) for chart seeding. |
| `GET` | `/api/flows` | Paginated flow table. Filters: `app`, `domain`, `ip`, `proto`, `state`, `rule_match`, `quick_filter`, `search`, `limit`, `offset`, `sort_by`, `order`. |
| `GET` | `/api/flows/{flow_id}` | Detailed flow record for deep inspection drawer. |
| `GET` | `/api/findings` | Active and historical security findings (port scans, DGA DNS, high uploads, rule alerts). |
| `POST` | `/api/findings/{id}/acknowledge` | Acknowledges a security finding. |
| `GET` | `/api/apps` | Ranked application breakdown with byte volume and percentage share. |
| `GET` | `/api/domains` | Ranked domain breakdown with byte volume and percentage share. |
| `GET` | `/api/history` | Historical 1-minute aggregated rollups stored in SQLite (`?minutes=60`). |
| `GET` | `/api/rules` | Retrieves active rules from `rules.json`. |
| `PUT` | `/api/rules` | Updates active rules and persists to `rules.json` (requires auth when configured). |
| `POST` | `/api/analyze` | Multipart upload for offline PCAP batch DPI inspection and filtering. |
| `GET` | `/api/analyze/download/{id}` | Downloads filtered sanitized output PCAP by UUID4 token. |
| `WS` | `/ws/live` | Real-time 1 Hz telemetry push socket delivering summary, flows, and engine stats. |

### Authentication
When `NETSIGHT_API_KEY` is configured in the environment:
- Pass `X-API-Key: <token>` or `Authorization: Bearer <token>` on all REST calls.
- Connect to WebSocket with `?token=<token>` query parameter or auth headers.
> [!NOTE]
> `NETSIGHT_API_KEY` is designed to secure direct REST and WebSocket API access (e.g., programmatic ingestion, CLI scripts, SIEM forwarding, and external microservices). In standard demo/local setups, leaving `NETSIGHT_API_KEY` unset allows the embedded web dashboard to query endpoints without credentials. In production environments where API keys are enforced, front-end traffic should be terminated behind a reverse proxy (e.g., Nginx) that injects the key or validates session cookies.

---

## Performance & Empirical Benchmarks

All benchmarks were executed on a Release build (`-O3` / `/O2`) across full L7 Deep Packet Inspection (IPv4/IPv6/VLAN parsing, bidirectional 5-tuple LRU flow tracking, TLS ClientHello SNI & JA3 MD5 extraction, DNS Shannon entropy calculation, and Welford host fan-out profiling).

### 1. C++17 DPI Engine Throughput (`100,023` DPI Frames)

| Metric | Measured Value |
| :--- | :--- |
| **Total Packets Inspected** | `100,023` packets (`8.63 MB` / `9,054,054 bytes`) |
| **Total Execution Time** | `98.14 ms` (`0.0981 s`) |
| **Peak Packet Throughput** | **`1,019,143 packets/sec` (`1.02M pps`)** |
| **Effective Data Rate** | **`738.02 Mbps`** (~90.5 B avg handshake frame; ~12.2 Gbps @ 1500 B MTU) |
| **Per-Packet DPI Latency** | **`0.98 µs / packet`** (sub-microsecond) |

### 2. Collector Ingestion & Query Latency (`500` Requests, `100` Active Flows)

| Component / Endpoint | Median (p50) | 95th Percentile (p95) | Notes |
| :--- | :--- | :--- | :--- |
| **`FlowCache` In-Memory Query** | **`62.70 µs`** | **`148.10 µs`** | $O(1)$ `OrderedDict` LRU + $O(N \log k)$ `heapq` top-$k$ |
| **`GET /api/summary`** | **`7.17 ms`** | **`11.31 ms`** | Full L7 summary + active/total counters |
| **`GET /api/flows?limit=100`** | **`17.16 ms`** | **`23.60 ms`** | 100 flows with JA3, DNS entropy, and byte ratios |
| **TCP NDJSON Replay Accounting** | **`0.00% Loss`** | **`0.00% Loss`** | Verified at `0.0x` (unthrottled burst) and `10.0x` speeds |

### 3. Architectural Bounds & Test Coverage

* **Concurrent Flow Table Capacity:** `100,000` active bidirectional flows in C++ ($O(1)$ LRU splice) and `50,000` in Python `FlowCache`.
* **Host Reconnaissance Bounds:** `100,000` victim entries and `256` distinct ports/IPs per host using Welford's $O(1)$ running variance algorithm.
* **L7 Signatures & Heuristics:** `22` application protocols + 4 real-time security detectors (Firewall Rules, Horizontal/Vertical Port Scan, High-Entropy DNS $\ge 3.8$ bits/char, and Asymmetric Upload).
* **Automated Verification:** `30` unit, security, accounting, and end-to-end integration tests across C++ (`engine-tests`) and Python (`pytest`).

---

## Technical Constraints & Honest Boundaries

- **Decryption**: NetSight does not decrypt payload data. It operates strictly on transport metadata and unencrypted handshake headers.
- **Encrypted Client Hello (ECH)**: When ECH is enabled by a browser and CDN, the inner SNI is encrypted. NetSight reports the outer SNI and leverages DNS and JA3 heuristics.
- **Rule Action**: Rules in live capture mode operate as passive alerts (zero packet dropping in monitoring mode). Inline packet dropping is performed during offline PCAP batch processing mode (`--analyze`).
- **Storage Strategy**: SQLite with WAL mode holds 1-minute historical aggregate rollups rather than storing every raw packet, preserving disk space and maintaining high query performance without external database dependencies (with automated 7-day retention cleanup).

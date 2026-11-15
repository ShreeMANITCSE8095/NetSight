# NetSight Data Contract Specification

This document freezes the data contract between the C++ Engine, the Python Collector, and the React Dashboard.

---

## 1. Engine to Collector Transport: NDJSON over TCP

The C++ engine streams newline-delimited JSON (NDJSON) over a local TCP socket (`127.0.0.1:9999` by default).

### 1.1 Flow Record (`type: "flow"` or `"flow_end"`)
Emitted periodically for active flows and on termination/expiration (`flow_end`):

```json
{
  "v": 1,
  "type": "flow",
  "ts": 1731340800123,
  "flow_id": "192.168.1.100:54203 -> 13.107.42.14:443 (TCP)",
  "src_ip": "192.168.1.100",
  "dst_ip": "13.107.42.14",
  "src_port": 54203,
  "dst_port": 443,
  "proto": "TCP",
  "app": "MICROSOFT",
  "sni": "www.microsoft.com",
  "ja3": "771,4865-4866,0-43,,",
  "ja3_hash": "c102ad630b998a8301fc92d96c66f760",
  "generation": 0,
  "packets_in": 8,
  "packets_out": 6,
  "packets_total": 14,
  "bytes_in": 2400,
  "bytes_out": 1020,
  "bytes_total": 3420,
  "live_speed": 128500.0,
  "byte_ratio": 0.425,
  "duration_ms": 1240,
  "first_seen": 1731340798883,
  "last_seen": 1731340800123,
  "syn_count": 1,
  "syn_ack_count": 1,
  "fin_count": 0,
  "rst_count": 0,
  "tcp_flags": "ACK PSH",
  "dns_query": "",
  "dns_entropy": 0.0,
  "dns_record_type": 0,
  "src_distinct_dst_ips": 3,
  "src_distinct_dst_ports": 5,
  "state": "active",
  "rule_match": false,
  "rule_reason": ""
}
```

### 1.2 Stats Record (`type: "stats"`)
Emitted every 1 second:

```json
{
  "v": 1,
  "type": "stats",
  "ts": 1731340800123,
  "packets_total": 15420,
  "bytes_total": 12450123,
  "active_flows": 42,
  "total_flows": 156,
  "pps": 340.5,
  "bps": 2840000.0,
  "drops": 0
}
```

---

## 2. Dynamic Rules File (`rules.json`)

The Python collector writes `rules.json`; the C++ engine polls its file modification time every second and automatically reloads rules in memory with read-write locks (`std::shared_mutex`):

```json
{
  "block_apps": ["YOUTUBE", "TIKTOK"],
  "block_domains": ["malware.com", "crypto.io"],
  "block_ips": ["192.168.1.100"],
  "block_ports": [4444]
}
```

---

## 3. Collector REST Endpoints (JSON)

- `GET /api/health`:
  ```json
  {
    "status": "ok",
    "mode": "replay",
    "engine_connected": true,
    "uptime_sec": 420,
    "active_flows": 42,
    "binary_found": true
  }
  ```
- `GET /api/summary`:
  ```json
  {
    "current_bps": 2840000.0,
    "current_pps": 340.5,
    "active_flows": 42,
    "total_flows": 156,
    "total_bytes": 12450123,
    "top_app": "HTTPS",
    "top_domain": "www.youtube.com",
    "unlabeled_percent": 3.2,
    "alert_count": 1,
    "engine_connected": true,
    "mode": "replay",
    "drops": 0
  }
  ```
- `GET /api/rates?seconds=900`:
  Returns array of 1-second rate samples `[{ "timestamp": 1731340800, "bps": 2840000.0, "pps": 340.5, "active_flows": 42 }]` for real-time chart seeding.
- `GET /api/flows`:
  Query parameters: `app`, `domain`, `ip`, `proto`, `state`, `rule_match`, `quick_filter` (`flagged`, `unlabeled`, `upload_heavy`), `search`, `limit` (1-500), `offset` (0-10000), `sort_by` (`bytes`, `live_speed`, `packets`, `first_seen`, `last_seen`, `app`, `proto`, `duration`), `order` (`asc`, `desc`).
- `GET /api/flows/{flow_id}`:
  Returns single detailed `FlowRecord` for deep drawer inspection.
- `GET /api/findings`:
  Returns array of active and historical security findings (`Finding`).
- `POST /api/findings/{id}/acknowledge`:
  Marks a security finding as acknowledged.
- `GET /api/apps`:
  Returns array of apps sorted by total bytes, packet counts, and percentage share.
- `GET /api/domains`:
  Returns array of domains sorted by total bytes and flow count.
- `GET /api/history?minutes=60`:
  1-minute aggregated time series buckets for charts (`timestamp`, `bps`, `pps`, `app_breakdown`).
- `GET /api/rules` & `PUT /api/rules`:
  Reads or updates rules in `rules.json` (requires authentication if `NETSIGHT_API_KEY` is configured).
- `POST /api/analyze`:
  Multipart PCAP upload for batch offline analysis. Returns job summary and `download_url`.
- `GET /api/analyze/download/{job_id}`:
  Download filtered PCAP artifact by 36-character UUID4 job token.

### Authentication
When `NETSIGHT_API_KEY` is set, API requests require:
`X-API-Key: <token>` or `Authorization: Bearer <token>`.
WebSocket connections authenticate via query parameter `?token=<token>` or header.

---

## 4. WebSocket Live Feed (`/ws/live`)

Broadcasts a delta payload once every 1 second:
```json
{
  "type": "tick",
  "summary": { ... },
  "active_flows": [ ... ],
  "stats": { ... }
}
```


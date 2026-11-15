"""In-memory sliding-window cache for active network flows and real-time aggregations."""

from collections import OrderedDict, deque
import time
import datetime
import hashlib
import heapq
import threading
from typing import Dict, List, Optional, Any
from .models import (
    FlowRecord,
    StatsRecord,
    SummaryResponse,
    AppBreakdown,
    DomainBreakdown,
    Finding,
    RatePoint,
)
from .database import Database


def display_app(app: str, dst_port: int = 0, src_port: int = 0, proto: str = "TCP") -> str:
    """Normalize raw app to a consistent display name. Unlabeled is explicit."""
    if not app or app.upper() in ("UNKNOWN", "OTHER"):
        if 443 in (dst_port, src_port):
            return "QUIC" if proto == "UDP" else "HTTPS"
        elif 80 in (dst_port, src_port):
            return "HTTP"
        elif 53 in (dst_port, src_port):
            return "DNS"
        return "Unlabeled"
    return app


class FlowCache:
    def __init__(self, max_flows: int = 50000, db: Optional[Database] = None):
        self.max_flows = max_flows
        self.db = db
        self._lock = threading.Lock()
        self.flows: OrderedDict[str, FlowRecord] = OrderedDict()
        self._pending_db_rows: List[Dict[str, Any]] = []
        self.latest_stats: StatsRecord = StatsRecord(
            total_packets=0,
            total_bytes=0,
            active_flows=0,
            total_flows=0,
            pps=0.0,
            bps=0.0,
            mode="replay",
            drops=None,
        )
        self.engine_connected = False
        self.mode = "replay"

        # Minute rollup accumulators
        self.minute_start_ts = int(time.time() // 60 * 60)
        self.minute_bytes = 0
        self.minute_packets = 0
        self.minute_app_data: Dict[str, Dict[str, int]] = {}
        self.minute_domain_data: Dict[str, Dict[str, Any]] = {}

        # 15-minute ring buffer of rate points (1 point per second, max 900)
        self.rates_history: deque = deque(maxlen=900)

        # Findings & Alert detections (server-side tracking)
        self.total_alerts: int = 0
        self.max_findings: int = 2000
        self.findings: OrderedDict[str, Finding] = OrderedDict()

    def _add_finding(self, finding: Finding) -> None:
        """Add finding with eviction of oldest acknowledged or oldest entry if full (S10)."""
        if finding.id in self.findings:
            self.findings[finding.id] = finding
            self.findings.move_to_end(finding.id)
            return

        if len(self.findings) >= self.max_findings:
            # Evict oldest acknowledged finding first
            evicted = False
            for k, f in list(self.findings.items()):
                if f.acknowledged:
                    del self.findings[k]
                    evicted = True
                    break
            if not evicted:
                self.findings.popitem(last=False)

        self.findings[finding.id] = finding
        self.total_alerts += 1

    def update_flow(self, flow: FlowRecord) -> None:
        """Update or insert a flow record and check real-time detectors."""
        with self._lock:
            fid = flow.flow_id
            flow.last_updated_ms = int(time.time() * 1000)

            # Compute JA3 MD5 hash if ja3 string is present
            if flow.ja3 and not flow.ja3_hash:
                flow.ja3_hash = hashlib.md5(flow.ja3.encode()).hexdigest()

            # Generational restart or counter wrap detection
            if fid in self.flows:
                existing = self.flows[fid]
                if (
                    getattr(flow, "generation", 0) > getattr(existing, "generation", 0)
                    or flow.bytes_total < existing.bytes_total
                ):
                    delta_bytes = flow.bytes_total
                    delta_pkts = flow.packets_total
                else:
                    delta_bytes = max(0, flow.bytes_total - existing.bytes_total)
                    delta_pkts = max(0, flow.packets_total - existing.packets_total)

                # Compute live throughput rate (bps)
                delta_t = ((flow.last_seen or 0) - (existing.last_seen or 0)) / 1000.0
                if delta_t > 0 and delta_bytes >= 0:
                    flow.live_speed = round((delta_bytes * 8.0) / delta_t, 1)
                else:
                    flow.live_speed = getattr(existing, "live_speed", 0.0)

                self.flows[fid] = flow
                self.flows.move_to_end(fid)
            else:
                delta_bytes = flow.bytes_total
                delta_pkts = flow.packets_total
                flow.live_speed = 0.0
                self.flows[fid] = flow

                # O(1) LRU eviction if beyond capacity
                if len(self.flows) > self.max_flows:
                    self.flows.popitem(last=False)

            # Run Findings Detectors
            self._inspect_flow_for_findings(flow)

            # Update minute rollups
            self.minute_bytes += delta_bytes
            self.minute_packets += delta_pkts

            app = display_app(flow.app, flow.dst_port, flow.src_port, flow.proto)
            if app not in self.minute_app_data:
                self.minute_app_data[app] = {"bytes": 0, "packets": 0}
            self.minute_app_data[app]["bytes"] += delta_bytes
            self.minute_app_data[app]["packets"] += delta_pkts

            if flow.sni:
                dom = flow.sni
                if dom not in self.minute_domain_data:
                    self.minute_domain_data[dom] = {
                        "app": app,
                        "bytes": 0,
                        "packets": 0,
                    }
                elif app not in ("Unlabeled", "DNS"):
                    self.minute_domain_data[dom]["app"] = app
                self.minute_domain_data[dom]["bytes"] += delta_bytes
                self.minute_domain_data[dom]["packets"] += delta_pkts

    def end_flow(self, flow: FlowRecord) -> None:
        """Merge final flow metrics and mark flow as closed."""
        flow.state = "closed"
        self.update_flow(flow)

    def update_stats(self, stats: StatsRecord) -> None:
        with self._lock:
            self.latest_stats = stats
            self.mode = stats.mode
            active_cnt = sum(1 for f in self.flows.values() if f.state != "closed")

            # Record 1-second rate point for UI seed
            now_ts = int(time.time())
            self.rates_history.append(
                RatePoint(
                    timestamp=now_ts,
                    bps=round(stats.bps, 1),
                    pps=round(stats.pps, 1),
                    active_flows=active_cnt,
                )
            )

    def set_engine_connected(self, connected: bool) -> None:
        with self._lock:
            self.engine_connected = connected
            if not connected:
                self.latest_stats.bps = 0.0
                self.latest_stats.pps = 0.0

    def get_flow_by_id(self, flow_id: str) -> Optional[FlowRecord]:
        with self._lock:
            return self.flows.get(flow_id)

    def _inspect_flow_for_findings(self, flow: FlowRecord) -> None:
        """Evaluate the 4 core defensible detectors against the flow."""
        now_iso = (
            flow.last_seen_iso
            or datetime.datetime.now(datetime.timezone.utc).isoformat()
        )

        # 1. Rule Match Detector
        if flow.rule_match:
            fid_rule = f"rule-{flow.flow_id}"
            if fid_rule not in self.findings:
                self._add_finding(Finding(
                    id=fid_rule,
                    timestamp_iso=now_iso,
                    detector="rule",
                    severity="high",
                    title=f"Rule Policy Match: {flow.rule_reason}",
                    flow_id=flow.flow_id,
                    src=f"{flow.src_ip}:{flow.src_port}",
                    dst=f"{flow.dst_ip}:{flow.dst_port}",
                    app=flow.app,
                    domain=flow.sni or None,
                    details=f"Flow matched engine security rule: {flow.rule_reason}.",
                ))

        # 2. Port Scan / Reconnaissance Detector
        if flow.src_distinct_dst_ports >= 15 or flow.src_distinct_dst_ips >= 15:
            fid_scan = f"scan-{flow.src_ip}"
            if fid_scan not in self.findings:
                self._add_finding(Finding(
                    id=fid_scan,
                    timestamp_iso=now_iso,
                    detector="port_scan",
                    severity="high",
                    title=f"Horizontal Port Scan from {flow.src_ip}",
                    flow_id=flow.flow_id,
                    src=f"{flow.src_ip}:{flow.src_port}",
                    dst=f"{flow.dst_ip}:{flow.dst_port}",
                    app=flow.app,
                    domain=flow.sni or None,
                    details=f"Source probed {flow.src_distinct_dst_ports} ports and {flow.src_distinct_dst_ips} hosts in short succession.",
                ))

        # 3. High-Entropy DNS Detector (E14)
        if flow.dns_entropy >= 3.8 and len(flow.dns_query) >= 8:
            fid_dns = f"dns-entropy-{flow.dns_query}"
            if fid_dns not in self.findings:
                self._add_finding(Finding(
                    id=fid_dns,
                    timestamp_iso=now_iso,
                    detector="high_entropy_dns",
                    severity="medium",
                    title=f"High-Entropy DNS Label: {flow.dns_query}",
                    flow_id=flow.flow_id,
                    src=f"{flow.src_ip}:{flow.src_port}",
                    dst=f"{flow.dst_ip}:{flow.dst_port}",
                    app=flow.app,
                    domain=flow.dns_query,
                    details=f"Calculated Shannon entropy on registrable label is {round(flow.dns_entropy, 2)} bits (threshold 3.8).",
                ))

        # 4. Large Asymmetric Upload Detector
        if (
            flow.bytes_out > 2_000_000
            and flow.bytes_out > 5 * max(1, flow.bytes_in)
        ):
            fid_upload = f"upload-{flow.flow_id}"
            if fid_upload not in self.findings:
                kb_out = flow.bytes_out // 1024
                self._add_finding(Finding(
                    id=fid_upload,
                    timestamp_iso=now_iso,
                    detector="upload_heavy",
                    severity="medium",
                    title=f"Large Asymmetric Upload ({kb_out} KB)",
                    flow_id=flow.flow_id,
                    src=f"{flow.src_ip}:{flow.src_port}",
                    dst=f"{flow.dst_ip}:{flow.dst_port}",
                    app=flow.app,
                    domain=flow.sni or None,
                    details=f"Flow transferred {kb_out} KB outbound with high asymmetry ({round(flow.byte_ratio, 2)}:1 out/in ratio).",
                ))

    def get_findings(self) -> List[Finding]:
        """Return all findings sorted with unacknowledged and recent first."""
        with self._lock:
            result = list(self.findings.values())
        result.sort(key=lambda x: (not x.acknowledged, x.timestamp_iso), reverse=True)
        return result

    def acknowledge_finding(self, finding_id: str) -> bool:
        with self._lock:
            if finding_id in self.findings:
                self.findings[finding_id].acknowledged = True
                return True
        return False

    def get_rates(self, seconds: int = 900) -> List[RatePoint]:
        """Return recent 1-second rate history up to N seconds."""
        with self._lock:
            if not self.rates_history:
                return []
            items = list(self.rates_history)
        if seconds and len(items) > seconds:
            return items[-seconds:]
        return items

    def get_summary(self) -> SummaryResponse:
        with self._lock:
            active_cnt = sum(1 for f in self.flows.values() if f.state != "closed")
            total_cnt = len(self.flows)

            # Determine top app and domain
            app_bytes: Dict[str, int] = {}
            domain_bytes: Dict[str, int] = {}
            unlabeled_bytes = 0
            total_b = 0

            for f in self.flows.values():
                app = display_app(f.app, f.dst_port, f.src_port, f.proto)
                b = f.bytes_total
                total_b += b
                if app == "Unlabeled":
                    unlabeled_bytes += b
                app_bytes[app] = app_bytes.get(app, 0) + b
                if f.sni:
                    domain_bytes[f.sni] = domain_bytes.get(f.sni, 0) + b

            top_app = max(app_bytes.items(), key=lambda x: x[1])[0] if app_bytes else "None"
            top_domain = max(domain_bytes.items(), key=lambda x: x[1])[0] if domain_bytes else "None"
            unlabeled_pct = round((unlabeled_bytes * 100.0 / total_b), 1) if total_b > 0 else 0.0

            return SummaryResponse(
                current_bps=self.latest_stats.bps,
                current_pps=self.latest_stats.pps,
                active_flows=active_cnt,
                total_flows=self.latest_stats.total_flows or total_cnt,
                total_bytes=self.latest_stats.total_bytes or total_b,
                top_app=top_app,
                top_domain=top_domain,
                unlabeled_percent=unlabeled_pct,
                alert_count=self.total_alerts,
                engine_connected=self.engine_connected,
                mode=self.mode,
                drops=self.latest_stats.drops,
            )

    def get_flows(
        self,
        app: Optional[str] = None,
        domain: Optional[str] = None,
        ip: Optional[str] = None,
        proto: Optional[str] = None,
        state: Optional[str] = None,
        rule_match: Optional[bool] = None,
        quick_filter: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "bytes",
        order: str = "desc",
    ) -> Dict[str, Any]:
        """Query flows with filtering, pagination, and sorting."""
        limit = max(1, min(limit, 500))
        offset = max(0, min(offset, 10000))

        with self._lock:
            flows_list = list(self.flows.values())

        if app:
            app_lower = app.lower()
            flows_list = [f for f in flows_list if app_lower in f.app.lower()]

        if domain:
            dom_lower = domain.lower()
            flows_list = [f for f in flows_list if dom_lower in f.sni.lower()]

        if ip:
            # C9: Exact IP matching to prevent 10.0.0.1 matching 10.0.0.15
            flows_list = [f for f in flows_list if f.src_ip == ip or f.dst_ip == ip]

        if proto:
            p_upper = proto.upper()
            flows_list = [f for f in flows_list if f.proto.upper() == p_upper]

        if state:
            s_lower = state.lower()
            flows_list = [f for f in flows_list if f.state.lower() == s_lower]

        if rule_match is not None:
            flows_list = [f for f in flows_list if f.rule_match == rule_match]

        if quick_filter == "unlabeled":
            flows_list = [f for f in flows_list if f.app in ("Unlabeled", "UNKNOWN")]
        elif quick_filter == "upload_heavy":
            flows_list = [f for f in flows_list if f.bytes_out > f.bytes_in * 5 and f.bytes_out > 2000000]

        if search:
            s_lower = search.lower()
            flows_list = [
                f for f in flows_list
                if s_lower in f.app.lower() or s_lower in f.sni.lower() or s_lower in f.src_ip or s_lower in f.dst_ip
            ]

        total_matching = len(flows_list)

        # Zero out live_speed on any flow that is closed or has not been seen in the last 2 poll intervals (4s)
        now_ms = int(time.time() * 1000)
        stale_cutoff_ms = now_ms - 4000
        for f in flows_list:
            last_up = getattr(f, "last_updated_ms", None) or f.last_seen or 0
            if f.state == "closed" or last_up < stale_cutoff_ms:
                f.live_speed = 0.0

        # Sorting
        reverse = order.lower() == "desc"
        sort_keys = {
            "bytes": lambda x: x.bytes_total,
            "packets": lambda x: x.packets_total,
            "first_seen": lambda x: x.first_seen or 0,
            "last_seen": lambda x: x.last_seen or 0,
            "live_speed": lambda x: getattr(x, "live_speed", 0.0) or 0.0,
            "app": lambda x: x.app,
            "proto": lambda x: x.proto,
            "duration": lambda x: x.duration_sec,
        }
        key_fn = sort_keys.get(sort_by, lambda x: x.bytes_total)
        target_k = offset + limit
        if target_k < total_matching and target_k <= 1000:
            top_k = (
                heapq.nlargest(target_k, flows_list, key=key_fn)
                if reverse
                else heapq.nsmallest(target_k, flows_list, key=key_fn)
            )
            paginated = top_k[offset : offset + limit]
        else:
            flows_list.sort(key=key_fn, reverse=reverse)
            paginated = flows_list[offset : offset + limit]

        return {
            "total": total_matching,
            "limit": limit,
            "offset": offset,
            "flows": paginated,
        }

    def get_apps(self, minutes: Optional[int] = None) -> List[AppBreakdown]:
        """Aggregate traffic volume by application with percentage share."""
        if minutes and self.db:
            rows = self.db.get_aggregated_apps(minutes=minutes)
            return [
                AppBreakdown(
                    app=r["app"],
                    bytes=r["bytes"],
                    packets=r["packets"],
                    flows=0,
                    share_percent=r["share_percent"],
                )
                for r in rows
            ]

        apps: Dict[str, Dict[str, int]] = {}
        total_bytes = 0

        with self._lock:
            flows_snapshot = list(self.flows.values())

        for f in flows_snapshot:
            app = display_app(f.app, f.dst_port, f.src_port, f.proto)
            if app not in apps:
                apps[app] = {"bytes": 0, "packets": 0, "flows": 0}
            apps[app]["bytes"] += f.bytes_total
            apps[app]["packets"] += f.packets_total
            apps[app]["flows"] += 1
            total_bytes += f.bytes_total

        breakdown = []
        for app, data in apps.items():
            pct = (data["bytes"] * 100.0 / total_bytes) if total_bytes > 0 else 0.0
            breakdown.append(
                AppBreakdown(
                    app=app,
                    bytes=data["bytes"],
                    packets=data["packets"],
                    flows=data["flows"],
                    share_percent=round(pct, 1),
                )
            )

        breakdown.sort(key=lambda x: x.bytes, reverse=True)
        return breakdown

    def get_domains(self, minutes: Optional[int] = None) -> List[DomainBreakdown]:
        """Aggregate traffic volume by detected domain."""
        if minutes and self.db:
            rows = self.db.get_aggregated_domains(minutes=minutes)
            return [
                DomainBreakdown(
                    domain=r["domain"],
                    app=r["app"],
                    bytes=r["bytes"],
                    packets=r["packets"],
                    flows=0,
                    share_percent=r["share_percent"],
                )
                for r in rows
            ]

        domains: Dict[str, Dict[str, Any]] = {}
        total_bytes = 0

        with self._lock:
            flows_snapshot = list(self.flows.values())

        for f in flows_snapshot:
            if not f.sni:
                continue
            dom = f.sni
            app = display_app(f.app, f.dst_port, f.src_port, f.proto)
            if dom not in domains:
                domains[dom] = {"app": app, "bytes": 0, "packets": 0, "flows": 0}
            elif app not in ("Unlabeled", "DNS"):
                domains[dom]["app"] = app

            domains[dom]["bytes"] += f.bytes_total
            domains[dom]["packets"] += f.packets_total
            domains[dom]["flows"] += 1
            total_bytes += f.bytes_total

        breakdown = []
        for dom, data in domains.items():
            pct = (data["bytes"] * 100.0 / total_bytes) if total_bytes > 0 else 0.0
            breakdown.append(
                DomainBreakdown(
                    domain=dom,
                    app=data["app"],
                    bytes=data["bytes"],
                    packets=data["packets"],
                    flows=data["flows"],
                    share_percent=round(pct, 1),
                )
            )

        breakdown.sort(key=lambda x: x.bytes, reverse=True)
        return breakdown

    def harvest_minute_rollup(self) -> Optional[Dict[str, Any]]:
        """Harvest the completed minute's counters for database storage."""
        with self._lock:
            now_minute = int(time.time() // 60 * 60)
            if now_minute > self.minute_start_ts:
                # Atomic reference swaps under lock
                app_data, self.minute_app_data = self.minute_app_data, {}
                domain_data, self.minute_domain_data = self.minute_domain_data, {}
                m_bytes, self.minute_bytes = self.minute_bytes, 0
                m_pkts, self.minute_packets = self.minute_packets, 0
                prev_ts = self.minute_start_ts
                self.minute_start_ts = now_minute

                rollup = {
                    "minute_ts": prev_ts,
                    "total_bytes": m_bytes,
                    "total_packets": m_pkts,
                    "bps": round((m_bytes * 8.0) / 60.0, 1),
                    "pps": round(m_pkts / 60.0, 1),
                    "active_flows": len(self.flows),
                    "app_data": app_data,
                    "domain_data": domain_data,
                }
                return rollup
        return None

    def prune_stale_closed_flows(self, max_closed_age_sec: int = 120) -> None:
        """Prune closed flows that have been inactive longer than max_closed_age_sec."""
        with self._lock:
            if not self.flows:
                return
            now_ms = int(time.time() * 1000)
            cutoff_ms = now_ms - (max_closed_age_sec * 1000)
            stale_keys = [
                fid
                for fid, f in self.flows.items()
                if (f.state == "closed" or not self.engine_connected)
                and 0 < (f.last_seen or 0) < cutoff_ms
            ]
            for fid in stale_keys:
                self.flows.pop(fid, None)

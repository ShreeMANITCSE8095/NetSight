"""Pydantic data models for NetSight collector validation and serialization."""

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Optional, Dict, Any
import ipaddress


VALID_APPS = {
    "HTTP", "HTTPS", "DNS", "TLS", "QUIC", "GOOGLE", "FACEBOOK", "YOUTUBE",
    "TWITTER", "INSTAGRAM", "WHATSAPP", "NETFLIX", "AMAZON", "MICROSOFT", "APPLE",
    "TELEGRAM", "TIKTOK", "SPOTIFY", "ZOOM", "DISCORD", "GITHUB", "CLOUDFLARE"
}


class FlowRecord(BaseModel):
    flow_id: str = Field(..., max_length=128)
    src_ip: str = Field(..., max_length=64)
    dst_ip: str = Field(..., max_length=64)
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    proto: str = Field(default="TCP", max_length=16)
    app: str = Field(default="UNKNOWN", max_length=64)
    sni: str = Field(default="", max_length=256)
    ja3: str = Field(default="", max_length=1024)
    ja3_hash: str = Field(default="", max_length=64)
    state: str = Field(default="active", max_length=32)
    action: str = Field(default="forward", max_length=32)
    packets_in: int = Field(default=0, ge=0)
    packets_out: int = Field(default=0, ge=0)
    bytes_in: int = Field(default=0, ge=0)
    bytes_out: int = Field(default=0, ge=0)
    packets_total: int = Field(default=0, ge=0)
    bytes_total: int = Field(default=0, ge=0)
    byte_ratio: float = 0.0
    live_speed: float = 0.0
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    first_seen_iso: Optional[str] = Field(default=None, max_length=64)
    last_seen_iso: Optional[str] = Field(default=None, max_length=64)
    duration_sec: float = 0.0
    syn_count: int = Field(default=0, ge=0)
    syn_ack_count: int = Field(default=0, ge=0)
    fin_count: int = Field(default=0, ge=0)
    rst_count: int = Field(default=0, ge=0)
    tcp_flags: str = Field(default="", max_length=32)
    dns_query: str = Field(default="", max_length=256)
    dns_entropy: float = 0.0
    dns_record_type: int = Field(default=0, ge=0, le=65535)
    src_distinct_dst_ips: int = Field(default=0, ge=0)
    src_distinct_dst_ports: int = Field(default=0, ge=0)
    rule_match: bool = False
    rule_reason: str = Field(default="", max_length=256)
    generation: int = Field(default=0, ge=0)
    last_updated_ms: Optional[int] = None


class StatsRecord(BaseModel):
    total_packets: int = 0
    total_bytes: int = 0
    packets_total: Optional[int] = None
    bytes_total: Optional[int] = None
    active_flows: int = 0
    total_flows: int = 0
    pps: float = 0.0
    bps: float = 0.0
    mode: str = "replay"
    drops: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def standardize_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "total_bytes" not in data and "bytes_total" in data:
                data["total_bytes"] = data["bytes_total"]
            elif "bytes_total" not in data and "total_bytes" in data:
                data["bytes_total"] = data["total_bytes"]

            if "total_packets" not in data and "packets_total" in data:
                data["total_packets"] = data["packets_total"]
            elif "packets_total" not in data and "total_packets" in data:
                data["packets_total"] = data["total_packets"]
        return data


class SummaryResponse(BaseModel):
    current_bps: float = 0.0
    current_pps: float = 0.0
    active_flows: int = 0
    total_flows: int = 0
    total_bytes: int = 0
    top_app: str = "None"
    top_domain: str = "None"
    unlabeled_percent: float = 0.0
    alert_count: int = 0
    engine_connected: bool = False
    mode: str = "replay"
    drops: Optional[int] = None


class HealthResponse(BaseModel):
    status: str = "ok"
    mode: str = "replay"
    engine_connected: bool = False
    uptime_sec: int = 0
    active_flows: int = 0
    binary_found: bool = False


class AppBreakdown(BaseModel):
    app: str
    bytes: int
    packets: int
    flows: int
    share_percent: float


class DomainBreakdown(BaseModel):
    domain: str
    app: str
    bytes: int
    packets: int
    flows: int
    share_percent: float


class HistoryPoint(BaseModel):
    minute: int
    timestamp_iso: str
    bps: float
    pps: float
    total_bytes: int
    total_packets: int = 0
    active_flows: int = 0
    app_breakdown: dict[str, int] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    timestamp_iso: str
    detector: str  # "rule", "port_scan", "high_entropy_dns", "upload_heavy"
    severity: str  # "high", "medium", "low"
    title: str
    flow_id: str
    src: str
    dst: str
    app: str = "Unlabeled"
    domain: Optional[str] = None
    details: str
    acknowledged: bool = False


class RatePoint(BaseModel):
    timestamp: int
    bps: float
    pps: float
    active_flows: int


class RulesPayload(BaseModel):
    block_apps: List[str] = Field(default_factory=list)
    block_domains: List[str] = Field(default_factory=list)
    block_ips: List[str] = Field(default_factory=list)
    block_ports: List[int] = Field(default_factory=list)

    @field_validator("block_apps")
    @classmethod
    def validate_apps(cls, apps: List[str]) -> List[str]:
        cleaned = []
        for a in apps:
            app_str = a.strip().upper()
            if app_str:
                if app_str not in VALID_APPS:
                    raise ValueError(f"Unknown app '{a}'. Valid apps: {sorted(VALID_APPS)}")
                cleaned.append(app_str)
        return list(dict.fromkeys(cleaned))

    @field_validator("block_domains")
    @classmethod
    def validate_domains(cls, domains: List[str]) -> List[str]:
        cleaned = []
        for d in domains:
            dom = d.strip().lower()
            if dom.startswith("http://"):
                dom = dom[7:]
            elif dom.startswith("https://"):
                dom = dom[8:]
            if "/" in dom:
                dom = dom.split("/")[0]
            if ":" in dom:
                dom = dom.split(":")[0]
            if dom.startswith("*."):
                dom = dom[2:]
            dom = dom.rstrip(".")
            if dom:
                cleaned.append(dom)
        return list(dict.fromkeys(cleaned))

    @field_validator("block_ports")
    @classmethod
    def validate_ports(cls, ports: List[int]) -> List[int]:
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} out of valid range (1-65535)")
        return sorted(set(ports))

    @field_validator("block_ips")
    @classmethod
    def validate_ips(cls, ips: List[str]) -> List[str]:
        cleaned = []
        for ip in ips:
            ip_str = ip.strip()
            if ip_str:
                ipaddress.ip_network(ip_str, strict=False)  # Validates IPv4/IPv6 or CIDR
                cleaned.append(ip_str)
        return list(dict.fromkeys(cleaned))

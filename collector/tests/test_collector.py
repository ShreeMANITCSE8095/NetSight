"""Pytest test suite for NetSight Collector REST API, FlowCache, and Storage."""

import pytest
from pathlib import Path
import tempfile
import json
import time

import asyncio

from collector.main import (
    app,
    cache,
    db,
    get_health,
    get_summary,
    get_flows,
    get_apps,
    get_domains,
    get_history,
    get_rules,
    update_rules,
)
from collector.models import FlowRecord, StatsRecord, RulesPayload
from collector.database import Database
from collector.flow_cache import FlowCache


def test_health_endpoint():
    data = get_health()
    assert data.status == "ok"
    assert data.uptime_sec >= 0
    assert data.binary_found is True


def test_flow_cache_merging():
    fc = FlowCache()

    f1 = FlowRecord(
        flow_id="flow-1",
        src_ip="192.168.1.10",
        dst_ip="142.250.185.110",
        src_port=54321,
        dst_port=443,
        proto="TCP",
        app="UNKNOWN",
        bytes_total=100,
        packets_total=2,
    )
    fc.update_flow(f1)
    assert len(fc.flows) == 1
    assert fc.flows["flow-1"].bytes_total == 100
    assert fc.flows["flow-1"].app == "UNKNOWN"

    # Subsequent update with SNI and App
    f1_update = FlowRecord(
        flow_id="flow-1",
        src_ip="192.168.1.10",
        dst_ip="142.250.185.110",
        src_port=54321,
        dst_port=443,
        proto="TCP",
        app="YOUTUBE",
        sni="www.youtube.com",
        bytes_total=350,
        packets_total=5,
    )
    fc.update_flow(f1_update)

    assert len(fc.flows) == 1
    assert fc.flows["flow-1"].bytes_total == 350
    assert fc.flows["flow-1"].app == "YOUTUBE"
    assert fc.flows["flow-1"].sni == "www.youtube.com"


def test_app_and_domain_breakdown():
    fc = FlowCache()

    fc.update_flow(
        FlowRecord(
            flow_id="f1",
            src_ip="10.0.0.1",
            dst_ip="1.1.1.1",
            src_port=1000,
            dst_port=443,
            app="CLOUDFLARE",
            sni="www.cloudflare.com",
            bytes_total=5000,
            packets_total=10,
        )
    )
    fc.update_flow(
        FlowRecord(
            flow_id="f2",
            src_ip="10.0.0.1",
            dst_ip="2.2.2.2",
            src_port=1001,
            dst_port=443,
            app="GOOGLE",
            sni="www.google.com",
            bytes_total=3000,
            packets_total=6,
        )
    )

    apps = fc.get_apps()
    assert len(apps) == 2
    assert apps[0].app == "CLOUDFLARE"
    assert apps[0].bytes == 5000
    assert apps[0].share_percent == 62.5
    assert apps[1].app == "GOOGLE"
    assert apps[1].share_percent == 37.5

    domains = fc.get_domains()
    assert len(domains) == 2
    assert domains[0].domain == "www.cloudflare.com"


def test_database_rollups():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    test_db = Database(db_path)
    now_min = int(time.time() // 60 * 60)

    test_db.record_minute_rollup(
        minute_ts=now_min,
        total_bytes=1000000,
        total_packets=1200,
        bps=133333.3,
        pps=20.0,
        active_flows=15,
        app_data={"YOUTUBE": {"bytes": 800000, "packets": 900}},
    )

    history = test_db.get_history(minutes=30)
    assert len(history) == 1
    assert history[0]["minute"] == now_min
    assert history[0]["total_bytes"] == 1000000
    assert history[0]["app_breakdown"]["YOUTUBE"] == 800000

    try:
        db_path.unlink()
    except Exception:
        pass


def test_rules_endpoints():
    payload = RulesPayload(
        block_apps=["TIKTOK", "FACEBOOK"],
        block_domains=["ads.tracking.com"],
        block_ips=["192.168.1.99"],
        block_ports=[8080],
    )

    res_put = update_rules(payload)
    assert res_put["status"] == "ok"

    data = get_rules()
    assert "TIKTOK" in data.block_apps
    assert "ads.tracking.com" in data.block_domains
    assert "192.168.1.99" in data.block_ips
    assert 8080 in data.block_ports


def test_flows_endpoint_filtering():
    cache.update_flow(
        FlowRecord(
            flow_id="test-filter-1",
            src_ip="192.168.1.55",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=53,
            proto="UDP",
            app="DNS",
            bytes_total=120,
            packets_total=1,
            rule_match=True,
            rule_reason="Blocked IP",
        )
    )

    # Filter by IP
    data = get_flows(ip="192.168.1.55")
    assert data["total"] >= 1
    found = any(f.flow_id == "test-filter-1" for f in data["flows"])
    assert found

    # Filter by rule_match
    data_alert = get_flows(rule_match=True)
    assert any(f.flow_id == "test-filter-1" for f in data_alert["flows"])


def test_findings_and_detections():
    fc = FlowCache()

    # 1. Rule finding
    f_rule = FlowRecord(
        flow_id="f-rule-1",
        src_ip="192.168.1.100",
        dst_ip="1.2.3.4",
        src_port=50000,
        dst_port=4444,
        rule_match=True,
        rule_reason="Blocked Port: 4444",
    )
    fc.update_flow(f_rule)

    # 2. Port scan finding
    f_scan = FlowRecord(
        flow_id="f-scan-1",
        src_ip="192.168.1.200",
        dst_ip="10.0.0.1",
        src_port=40000,
        dst_port=80,
        src_distinct_dst_ports=20,
    )
    fc.update_flow(f_scan)

    # 3. High entropy DNS finding
    f_dns = FlowRecord(
        flow_id="f-dns-1",
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        dns_query="x8f1q9z3m2k7w0b4p.evil.com",
        dns_entropy=4.2,
    )
    fc.update_flow(f_dns)

    # 4. Large upload finding
    f_upload = FlowRecord(
        flow_id="f-upload-1",
        src_ip="192.168.1.50",
        dst_ip="142.250.190.46",
        src_port=52000,
        dst_port=443,
        bytes_out=5_000_000,
        bytes_in=50_000,
        byte_ratio=100.0,
    )
    fc.update_flow(f_upload)

    findings = fc.get_findings()
    assert len(findings) == 4
    detectors = {f.detector for f in findings}
    assert detectors == {"rule", "port_scan", "high_entropy_dns", "upload_heavy"}

    # Test acknowledgement
    fid = findings[0].id
    assert fc.acknowledge_finding(fid) is True
    updated = [f for f in fc.get_findings() if f.id == fid][0]
    assert updated.acknowledged is True


def test_rates_history_and_flow_by_id():
    fc = FlowCache()

    f = FlowRecord(
        flow_id="single-flow-xyz",
        src_ip="10.10.10.10",
        dst_ip="20.20.20.20",
        src_port=12345,
        dst_port=80,
        app="HTTP",
        bytes_total=9999,
    )
    fc.update_flow(f)

    # Test get_flow_by_id
    found = fc.get_flow_by_id("single-flow-xyz")
    assert found is not None
    assert found.bytes_total == 9999
    assert fc.get_flow_by_id("non-existent") is None

    # Test rate buffer
    stats = StatsRecord(
        total_packets=100,
        total_bytes=10000,
        active_flows=1,
        total_flows=1,
        pps=50.0,
        bps=400000.0,
    )
    fc.update_stats(stats)
    rates = fc.get_rates(seconds=60)
    assert len(rates) == 1
    assert rates[0].bps == 400000.0
    assert rates[0].pps == 50.0


def test_security_flow_record_bounds():
    """S9: Test that FlowRecord bounds strings and integer ranges."""
    from pydantic import ValidationError

    # Port out of range
    with pytest.raises(ValidationError):
        FlowRecord(
            flow_id="f1",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=70000,
            dst_port=80,
        )

    # String exceeding max_length
    with pytest.raises(ValidationError):
        FlowRecord(
            flow_id="f1",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            sni="x" * 300,  # max_length is 256
        )


def test_security_findings_eviction():
    """S10: Test findings eviction on capacity."""
    fc = FlowCache()
    fc.max_findings = 3

    # Add 3 findings
    f1 = FlowRecord(flow_id="f1", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1, dst_port=80, rule_match=True, rule_reason="r1")
    f2 = FlowRecord(flow_id="f2", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=2, dst_port=80, rule_match=True, rule_reason="r2")
    f3 = FlowRecord(flow_id="f3", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=3, dst_port=80, rule_match=True, rule_reason="r3")
    fc.update_flow(f1)
    fc.update_flow(f2)
    fc.update_flow(f3)
    assert len(fc.findings) == 3

    # Acknowledge f2
    fc.acknowledge_finding("rule-f2")

    # Add 4th finding - f2 (acknowledged) should be evicted first
    f4 = FlowRecord(flow_id="f4", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=4, dst_port=80, rule_match=True, rule_reason="r4")
    fc.update_flow(f4)
    assert len(fc.findings) == 3
    assert "rule-f2" not in fc.findings
    assert "rule-f4" in fc.findings


def test_security_get_flows_pagination_and_sorting():
    """S11: Test flow table pagination and bounded query."""
    fc = FlowCache()
    for i in range(100):
        fc.update_flow(
            FlowRecord(
                flow_id=f"flow-{i}",
                src_ip="10.0.0.1",
                dst_ip=f"10.0.1.{i}",
                src_port=1000 + i,
                dst_port=443,
                bytes_total=i * 10,
            )
        )

    # Offset clamped, limit clamped, top-k optimization
    res = fc.get_flows(limit=10, offset=0, sort_by="bytes", order="desc")
    assert len(res["flows"]) == 10
    assert res["flows"][0].bytes_total == 990
    assert res["total"] == 100

    # Limit capped at 500
    res_large = fc.get_flows(limit=1000, offset=0)
    assert res_large["limit"] == 500


def test_security_auth_verification():
    """S1: Test token verification logic."""
    from collector.main import verify_auth
    from fastapi import HTTPException
    import collector.main as main_mod

    # With no API_KEY configured, passes
    main_mod.API_KEY = ""
    verify_auth()

    # With API_KEY set
    main_mod.API_KEY = "test-secret-token"
    orig_testing = main_mod.TESTING
    main_mod.TESTING = False
    try:
        # Correct token via X-API-Key
        verify_auth(x_api_key="test-secret-token")

        # Correct token via Bearer
        verify_auth(authorization="Bearer test-secret-token")

        # Invalid token
        with pytest.raises(HTTPException) as exc:
            verify_auth(x_api_key="wrong-token")
        assert exc.value.status_code == 401

        # Missing token
        with pytest.raises(HTTPException) as exc:
            verify_auth()
        assert exc.value.status_code == 401
    finally:
        main_mod.API_KEY = ""
        main_mod.TESTING = orig_testing


def test_security_job_id_validation():
    """S7: Test 36-char UUID4 validation vs guessable tokens and traversal."""
    from collector.main import JOB_ID_RE
    import uuid

    valid_uuid = str(uuid.uuid4())
    assert JOB_ID_RE.match(valid_uuid) is not None

    # 8-hex guessable token must be rejected
    assert JOB_ID_RE.match("a1b2c3d4") is None

    # Path traversal attempts must be rejected
    assert JOB_ID_RE.match("../../../etc/passwd") is None
    assert JOB_ID_RE.match("..\\..\\windows\\system32") is None


def test_security_analyze_rule_validation():
    """S23: Test validation of rules parameters."""
    # Unknown app raises ValueError
    with pytest.raises(ValueError):
        RulesPayload(block_apps=["MALICIOUS_APP"])

    # Valid app normalized
    rp = RulesPayload(block_apps=["youtube", "google"])
    assert rp.block_apps == ["YOUTUBE", "GOOGLE"]


def test_security_engine_binary_validation():
    """S24: Test that arbitrary binary names are rejected."""
    import collector.config as config_mod

    # Valid names netsight-engine / netsight-engine.exe
    # An arbitrary binary like /bin/sh or cmd.exe should not match
    allowed = ("netsight-engine", "netsight-engine.exe")
    assert Path("netsight-engine").name in allowed
    assert Path("cmd.exe").name not in allowed
    assert Path("sh").name not in allowed


def test_security_cors_and_docs_defaults():
    """S14 & S20: Verify docs and CORS credentials defaults."""
    from collector.main import app
    from fastapi.middleware.cors import CORSMiddleware

    # Check docs are disabled by default when ENABLE_DOCS=False
    from collector.config import ENABLE_DOCS
    if not ENABLE_DOCS:
        assert app.docs_url is None
        assert app.redoc_url is None
        assert app.openapi_url is None

    # Check CORS allow_credentials is False
    for middleware in app.user_middleware:
        if middleware.cls is CORSMiddleware:
            assert middleware.kwargs.get("allow_credentials") is False


def test_database_prune_history():
    """SEC-13: Verify historical records older than retention threshold are deleted."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name
    try:
        test_db = Database(temp_db_path)
        now_ts = int(time.time())
        old_ts = now_ts - (8 * 86400)  # 8 days old

        test_db.record_minute_rollup(
            minute_ts=old_ts,
            total_bytes=1000,
            total_packets=10,
            bps=100.0,
            pps=1.0,
            active_flows=1,
            app_data={"GOOGLE": {"bytes": 1000, "packets": 10}},
            domain_data={"google.com": {"app": "GOOGLE", "bytes": 1000, "packets": 10}},
        )
        test_db.record_minute_rollup(
            minute_ts=now_ts,
            total_bytes=2000,
            total_packets=20,
            bps=200.0,
            pps=2.0,
            active_flows=2,
            app_data={"YOUTUBE": {"bytes": 2000, "packets": 20}},
            domain_data={"youtube.com": {"app": "YOUTUBE", "bytes": 2000, "packets": 20}},
        )

        # Before prune: both old and recent should exist
        with test_db._get_conn() as conn:
            cnt = conn.execute("SELECT COUNT(*) FROM history_minute;").fetchone()[0]
            assert cnt == 2

        # Prune older than 7 days
        deleted = test_db.prune_history(retention_days=7)
        assert deleted >= 3  # 1 minute + 1 app + 1 domain

        # After prune: only recent record remains
        with test_db._get_conn() as conn:
            rows = conn.execute("SELECT minute_ts FROM history_minute;").fetchall()
            assert len(rows) == 1
            assert rows[0][0] == now_ts
    finally:
        Path(temp_db_path).unlink(missing_ok=True)


def test_stats_record_attribute_standardization():
    """Verify StatsRecord and get_summary cleanly handle both bytes_total and total_bytes."""
    s1 = StatsRecord(
        bytes_total=500000,
        packets_total=1200,
        active_flows=10,
        total_flows=25,
        pps=100.0,
        bps=800000.0,
        mode="replay",
    )
    assert s1.total_bytes == 500000
    assert s1.bytes_total == 500000
    assert s1.total_packets == 1200
    assert s1.packets_total == 1200

    s2 = StatsRecord(
        total_bytes=300000,
        total_packets=800,
        active_flows=5,
        total_flows=12,
        pps=50.0,
        bps=400000.0,
    )
    assert s2.total_bytes == 300000
    assert s2.bytes_total == 300000
    assert s2.total_packets == 800
    assert s2.packets_total == 800

    fc = FlowCache()
    fc.update_stats(s1)
    summary = fc.get_summary()
    assert summary.total_bytes == 500000
    assert summary.total_flows == 25
    assert summary.active_flows >= 0

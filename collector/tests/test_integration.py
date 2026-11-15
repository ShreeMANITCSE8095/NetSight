"""Integration test: Replays PCAP through netsight-engine.exe and verifies Collector ingestion."""

import asyncio
import subprocess
import time
from pathlib import Path

from collector.config import PROJECT_ROOT, ENGINE_BINARY
from collector.flow_cache import FlowCache
from collector.tcp_ingest import TcpIngestClient


def test_engine_collector_tcp_integration():
    pcap_path = PROJECT_ROOT / "test_data" / "test_dpi.pcap"
    assert pcap_path.exists(), f"PCAP not found: {pcap_path}"
    assert ENGINE_BINARY.exists(), f"Engine binary not found: {ENGINE_BINARY}"

    port = 9998
    # Start engine in replay mode on port 9998 with looping so we have time to ingest
    cmd = [
        str(ENGINE_BINARY),
        "--replay", str(pcap_path),
        "--port", str(port),
        "--speed", "10"
    ]
    engine_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(1.0)
    assert engine_proc.poll() is None, "Engine process exited prematurely"

    cache = FlowCache()
    client = TcpIngestClient("127.0.0.1", port, cache)

    async def ingest_runner():
        client.start()
        # Wait up to 3 seconds to gather flows
        for _ in range(30):
            await asyncio.sleep(0.1)
            if len(cache.flows) >= 5:
                break
        await client.stop()

    try:
        asyncio.run(ingest_runner())
    finally:
        engine_proc.terminate()
        try:
            engine_proc.wait(timeout=2.0)
        except Exception:
            engine_proc.kill()

    # Assertions on ingested data
    assert len(cache.flows) > 0, "No flows ingested into cache!"
    print(f"Total flows ingested: {len(cache.flows)}")

    summary = cache.get_summary()
    assert summary.active_flows > 0
    assert summary.total_bytes > 0
    print(f"Summary: active_flows={summary.active_flows}, total_bytes={summary.total_bytes}, top_app={summary.top_app}")

    apps = cache.get_apps()
    assert len(apps) > 0
    app_names = [a.app for a in apps]
    print(f"Discovered apps: {app_names}")

    # Verify that ARGUS parameters exist in flows
    flows_res = cache.get_flows(limit=10)
    sample_flow = flows_res["flows"][0]
    assert hasattr(sample_flow, "bytes_in")
    assert hasattr(sample_flow, "bytes_out")
    assert hasattr(sample_flow, "byte_ratio")
    assert hasattr(sample_flow, "ja3")
    assert hasattr(sample_flow, "dns_entropy")
    print(f"Sample flow {sample_flow.flow_id}: app={sample_flow.app}, bytes_in={sample_flow.bytes_in}, bytes_out={sample_flow.bytes_out}, ja3={sample_flow.ja3}")


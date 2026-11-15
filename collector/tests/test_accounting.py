"""Accounting verification: Verifies that engine flows and bytes match collector totals across replay speeds."""

import asyncio
import subprocess
import time
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from collector.config import PROJECT_ROOT, ENGINE_BINARY
from collector.flow_cache import FlowCache
from collector.tcp_ingest import TcpIngestClient


def run_speed_accounting(speed: float, port: int, max_wait_sec: float) -> tuple[int, int, int]:
    pcap_path = PROJECT_ROOT / "test_data" / "test_dpi.pcap"
    cmd = [
        str(ENGINE_BINARY),
        "--replay", str(pcap_path),
        "--port", str(port),
        "--speed", str(speed)
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)

    cache = FlowCache()
    client = TcpIngestClient("127.0.0.1", port, cache)

    async def runner():
        client.start()
        ticks = int(max_wait_sec * 10)
        for _ in range(ticks):
            await asyncio.sleep(0.1)
            if len(cache.flows) >= 27:
                break
        await client.stop()

    try:
        asyncio.run(runner())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()

    collector_flow_bytes = sum(f.bytes_total for f in cache.flows.values())
    return len(cache.flows), collector_flow_bytes, cache.minute_bytes


def test_accounting_speed_fastest():
    """Speed 0x (fastest possible) must ingest 100% of flows and bytes without dropping."""
    flows_cnt, total_bytes, minute_bytes = run_speed_accounting(0.0, 9993, max_wait_sec=4.0)
    assert flows_cnt == 27, f"Expected 27 flows, got {flows_cnt}"
    assert total_bytes == 5738, f"Expected 5738 bytes, got {total_bytes}"
    assert minute_bytes == total_bytes, f"Rollup mismatch: {minute_bytes} vs {total_bytes}"


def test_accounting_speed_10x():
    """Speed 10x must ingest 100% of flows and bytes within the replay window."""
    flows_cnt, total_bytes, minute_bytes = run_speed_accounting(10.0, 9994, max_wait_sec=9.0)
    assert flows_cnt == 27, f"Expected 27 flows, got {flows_cnt}"
    assert total_bytes == 5738, f"Expected 5738 bytes, got {total_bytes}"
    assert minute_bytes == total_bytes, f"Rollup mismatch: {minute_bytes} vs {total_bytes}"


if __name__ == "__main__":
    test_accounting_speed_fastest()
    print("test_accounting_speed_fastest PASSED")
    test_accounting_speed_10x()
    print("test_accounting_speed_10x PASSED")
    print("All replay accounting tests passed perfectly!")

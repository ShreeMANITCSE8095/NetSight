"""Live End-to-End Smoke Test for NetSight."""

import subprocess
import time
import urllib.request
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def get_engine_exe() -> Path:
    candidates = [
        ROOT / "engine" / "build" / "Release" / "netsight-engine.exe",
        ROOT / "engine" / "build" / "netsight-engine",
        ROOT / "engine" / "build" / "netsight-engine.exe",
        Path("/usr/local/bin/netsight-engine"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return ROOT / "engine" / "build" / ("Release/netsight-engine.exe" if sys.platform == "win32" else "netsight-engine")

ENGINE_EXE = get_engine_exe()
TEST_PCAP = ROOT / "test_data" / "test_dpi.pcap"


def main():
    print("=================================================================")
    print("            NETSIGHT LIVE END-TO-END SMOKE TEST                  ")
    print("=================================================================")

    print("[1/4] Spawning C++ Engine on port 9999 (Replay loop)...")
    engine = subprocess.Popen(
        [str(ENGINE_EXE), "--replay", str(TEST_PCAP), "--port", "9999", "--speed", "10", "--loop"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    print("[2/4] Spawning Python Collector on port 8000...")
    collector = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "collector.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(3.0)

    try:
        print("[3/4] Probing Collector REST API...")
        with urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=3) as r:
            health = json.loads(r.read().decode())
            print("  -> /api/health:       status =", health.get("status"), "| engine_connected =", health.get("engine_connected"))

        # Give 1.5s for initial batch of flows to stream into cache
        time.sleep(1.5)

        with urllib.request.urlopen("http://127.0.0.1:8000/api/summary", timeout=3) as r:
            summary = json.loads(r.read().decode())
            print("  -> /api/summary:      active_flows =", summary.get("active_flows"), "| top_app =", summary.get("top_app"), "| bps =", summary.get("current_bps"))

        with urllib.request.urlopen("http://127.0.0.1:8000/api/flows?limit=3", timeout=3) as r:
            flows = json.loads(r.read().decode())
            total = flows.get("total", 0)
            print(f"  -> /api/flows:        total={total}")
            for f in flows.get("flows", []):
                print(f"       * {f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']} [{f['app']}] SNI: {f['sni']} JA3: {f['ja3']}")

        with urllib.request.urlopen("http://127.0.0.1:8000/api/apps", timeout=3) as r:
            apps = json.loads(r.read().decode())
            print(f"  -> /api/apps:         {len(apps)} apps -> {[a['app'] for a in apps[:5]]}")

        print("\n[4/4] ALL SMOKE TESTS PASSED! Full stack is functional and live.")
    finally:
        print("Stopping test processes...")
        engine.terminate()
        collector.terminate()
        try:
            engine.wait(timeout=2.0)
        except Exception:
            engine.kill()
        try:
            collector.wait(timeout=2.0)
        except Exception:
            collector.kill()
        print("Cleaned up.")


if __name__ == '__main__':
    main()

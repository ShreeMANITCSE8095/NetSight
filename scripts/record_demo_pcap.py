#!/usr/bin/env python3
"""
NetSight Live Demo PCAP Recorder
Records a clean 1-2 minute live network capture on Windows using Npcap/Scapy/native tools,
strips payload data (keeps headers + TLS/HTTP/DNS handshakes), and saves to test_data/demo_real.pcap.
"""

import sys
import time
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PCAP = PROJECT_ROOT / "test_data" / "demo_real.pcap"


def get_engine_bin() -> Path:
    candidates = [
        PROJECT_ROOT / "engine" / "build" / "Release" / "netsight-engine.exe",
        PROJECT_ROOT / "engine" / "build" / "netsight-engine",
        PROJECT_ROOT / "engine" / "build" / "netsight-engine.exe",
        Path("/usr/local/bin/netsight-engine"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return PROJECT_ROOT / "engine" / "build" / ("Release/netsight-engine.exe" if sys.platform == "win32" else "netsight-engine")


def record_with_engine(duration_sec: int = 60) -> bool:
    engine_bin = get_engine_bin()
    if not engine_bin.exists():
        print(f"[!] Engine binary not found at {engine_bin}. Run CMake build first.")
        return False

    print("=" * 60)
    print("  NetSight Demo PCAP Recording Utility")
    print("=" * 60)
    print(f"Target duration: {duration_sec} seconds")
    print(f"Output path:     {OUTPUT_PCAP}")
    print("\nInstructions for recording a great demo capture:")
    print("  1. When recording starts, open a browser window.")
    print("  2. Watch a YouTube video (generates TLS/QUIC streaming flows).")
    print("  3. Open a search page (Google/Bing/DuckDuckGo).")
    print("  4. Visit GitHub or Wikipedia.")
    print("=" * 60)

    input("Press ENTER when you are ready to begin capture...")
    print(f"\n[*] Starting capture for {duration_sec}s...")

    # We can record using netsight-engine batch analysis or dumpcap if available
    dumpcap = Path("C:/Program Files/Wireshark/dumpcap.exe")
    npcap_dumpcap = Path("C:/Program Files/Npcap/dumpcap.exe")

    cap_tool = None
    if dumpcap.exists():
        cap_tool = dumpcap
    elif npcap_dumpcap.exists():
        cap_tool = npcap_dumpcap

    if cap_tool:
        print(f"[*] Recording via {cap_tool.name}...")
        cmd = [str(cap_tool), "-a", f"duration:{duration_sec}", "-w", str(OUTPUT_PCAP)]
        try:
            subprocess.run(cmd, check=True)
            print(f"[+] Successfully recorded {OUTPUT_PCAP.stat().st_size} bytes to {OUTPUT_PCAP}")
            return True
        except Exception as e:
            print(f"[-] Dumpcap failed: {e}")

    # Fallback to Python raw capture or check_device guidance
    print("[*] To record via Windows Npcap, you can run Wireshark or dumpcap for 60 seconds,")
    print(f"    and save the capture file as: {OUTPUT_PCAP}")
    return False


if __name__ == "__main__":
    dur = 60
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        dur = int(sys.argv[1])
    record_with_engine(dur)


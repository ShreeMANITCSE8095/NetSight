"""NetSight Engine Benchmark: Measures packet processing throughput and latency."""

import subprocess
import time
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if sys.platform == "win32":
    ENGINE_EXE = PROJECT_ROOT / "engine" / "build" / "Release" / "netsight-engine.exe"
else:
    ENGINE_EXE = PROJECT_ROOT / "engine" / "build" / "netsight-engine"

TEST_PCAP = PROJECT_ROOT / "test_data" / "test_dpi.pcap"
OUT_PCAP = PROJECT_ROOT / "test_data" / "bench_out.pcap"


def run_benchmark(iterations: int = 200):
    assert ENGINE_EXE.exists(), f"Engine binary missing at {ENGINE_EXE}"
    assert TEST_PCAP.exists(), f"Test PCAP missing at {TEST_PCAP}"

    file_size_bytes = TEST_PCAP.stat().st_size
    print("==========================================================")
    print("  NetSight C++ DPI Engine Throughput Benchmark            ")
    print("==========================================================")
    print(f"Target Binary: {ENGINE_EXE}")
    print(f"Input PCAP:    {TEST_PCAP} ({file_size_bytes} bytes)")
    print(f"Iterations:    {iterations}")
    print("----------------------------------------------------------")

    # Run one warmup pass
    subprocess.run([str(ENGINE_EXE), "--analyze", str(TEST_PCAP), str(OUT_PCAP)], capture_output=True)

    total_packets = 0
    start_time = time.perf_counter()

    for _ in range(iterations):
        res = subprocess.run([str(ENGINE_EXE), "--analyze", str(TEST_PCAP), str(OUT_PCAP)], capture_output=True, text=True)
        if res.returncode != 0:
            print("Engine failed during benchmark:", res.stderr)
            return

    elapsed_sec = time.perf_counter() - start_time
    total_packets = 77 * iterations  # 77 packets per pcap file
    total_bytes = file_size_bytes * iterations

    pps = total_packets / elapsed_sec
    mbps = (total_bytes * 8) / (elapsed_sec * 1_000_000)

    print(f"Total Packets Processed: {total_packets:,}")
    print(f"Total Data Processed:    {total_bytes / (1024*1024):.2f} MB")
    print(f"Total Execution Time:    {elapsed_sec:.3f} s")
    print("----------------------------------------------------------")
    print(f"Throughput (Packets/s):  {pps:,.0f} pkts/sec")
    print(f"Throughput (Bandwidth):  {mbps:.2f} Mbps")
    print(f"Average Packet Latency:  {(elapsed_sec / total_packets) * 1_000_000:.2f} us/packet")
    print("==========================================================")

    # Clean up benchmark output
    if OUT_PCAP.exists():
        OUT_PCAP.unlink()


if __name__ == "__main__":
    run_benchmark(iterations=100)


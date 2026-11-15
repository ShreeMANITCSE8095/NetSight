"""Device & Dependency Audit for NetSight Presentation."""

import sys
import os
import shutil
import socket

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

print("=================================================================")
print("       NETSIGHT: DEVICE & DEPENDENCY READINESS AUDIT             ")
print("=================================================================")

# 1. OS & Architecture
print(f"OS Platform:          {sys.platform} ({os.name})")
print(f"Python Version:       {sys.version.split()[0]}")

# 2. C++ Build Toolchain
cmake = shutil.which("cmake")
print(f"\n[Toolchain]")
print(f"  CMake:              {'OK -> ' + cmake if cmake else 'MISSING'}")

engine_bin = os.path.join(ROOT_DIR, "engine", "build", "Release", "netsight-engine.exe")
print(f"  Compiled Engine:    {'OK (Ready)' if os.path.exists(engine_bin) else 'MISSING (Run cmake --build)'}")

tests_bin = os.path.join(ROOT_DIR, "engine", "build", "Release", "engine-tests.exe")
print(f"  Engine Unit Tests:  {'OK (Ready)' if os.path.exists(tests_bin) else 'MISSING'}")

# 3. Python Packages
print(f"\n[Python Packages]")
packages = [
    ("fastapi", "FastAPI web framework"),
    ("uvicorn", "Uvicorn ASGI server"),
    ("pydantic", "Pydantic schema validation"),
    ("multipart", "python-multipart form parsing"),
    ("httpx", "HTTP client"),
    ("pytest", "Pytest test framework"),
    ("pytest_asyncio", "Pytest async support"),
]

for mod_name, desc in packages:
    try:
        __import__(mod_name)
        print(f"  {mod_name:18}: OK ({desc})")
    except ImportError:
        print(f"  {mod_name:18}: MISSING! ({desc})")

# 4. Frontend Toolchain
print(f"\n[Frontend Toolchain]")
node = shutil.which("node")
npm = shutil.which("npm")
print(f"  Node.js:            {'OK -> ' + node if node else 'MISSING'}")
print(f"  npm:                {'OK -> ' + npm if npm else 'MISSING'}")

dist_index = os.path.join(ROOT_DIR, "dashboard", "dist", "index.html")
print(f"  Dashboard Build:    {'OK (Ready)' if os.path.exists(dist_index) else 'MISSING (Run npm run build)'}")

# 5. Network Driver (Npcap)
print(f"\n[Capture Drivers (Npcap)]")
sys32 = os.environ.get("WINDIR", r"C:\Windows") + r"\System32"
wpcap_found = os.path.exists(os.path.join(sys32, "wpcap.dll")) or os.path.exists(os.path.join(sys32, "Npcap", "wpcap.dll"))
packet_found = os.path.exists(os.path.join(sys32, "Packet.dll")) or os.path.exists(os.path.join(sys32, "Npcap", "Packet.dll"))

if wpcap_found and packet_found:
    print("  Status:             Npcap driver detected. Live capture enabled.")
else:
    print("  Status:             Npcap NOT found.")
    print("                      NOTE: This is EXPECTED and SAFE.")
    print("                      Replay mode (--replay test_data/test_dpi.pcap) runs natively")
    print("                      without Npcap, feeds the full pipeline, and is 100% stable.")

# 6. Port Availability Check
print(f"\n[Port Availability (Localhost)]")
ports = [
    (9999, "C++ Engine NDJSON Stream"),
    (8000, "Python Collector REST / WS"),
    (5173, "React Dashboard UI"),
]

for port, service in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        print(f"  Port {port:5}:         FREE (Ready for {service})")
    except Exception as e:
        print(f"  Port {port:5}:         IN USE ({e}) - Caution: Kill existing process before demo")
    finally:
        s.close()

# 7. Test Data Check
print(f"\n[Test Data]")
test_pcap = os.path.join(ROOT_DIR, "test_data", "test_dpi.pcap")
print(f"  test_dpi.pcap:      {'OK (' + str(os.path.getsize(test_pcap)) + ' bytes)' if os.path.exists(test_pcap) else 'MISSING'}")

rules_file = os.path.join(ROOT_DIR, "rules.json")
print(f"  rules.json:         {'OK' if os.path.exists(rules_file) else 'MISSING'}")

print("=================================================================")
print("                   AUDIT COMPLETE                                ")
print("=================================================================")

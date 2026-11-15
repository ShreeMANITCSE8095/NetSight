"""NetSight Python Collector: FastAPI REST API, WebSocket, Ingest, and Rollup."""

import asyncio
import hmac
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, List, Set, Annotated
from fastapi import (
    FastAPI,
    UploadFile,
    File,
    Form,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    Query,
    Header,
    Depends,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

from .config import (
    ENGINE_HOST,
    ENGINE_PORT,
    DB_PATH,
    RULES_PATH,
    ENGINE_BINARY,
    UPLOAD_DIR,
    OUTPUT_DIR,
    CORS_ORIGINS,
    TESTING,
    API_KEY,
    ENABLE_DOCS,
)
from .models import (
    SummaryResponse,
    HealthResponse,
    AppBreakdown,
    DomainBreakdown,
    HistoryPoint,
    RulesPayload,
    FlowRecord,
    Finding,
    RatePoint,
)
from .database import Database
from .flow_cache import FlowCache
from .tcp_ingest import TcpIngestClient

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("NetSightCollector")

# S7: Full 36-char UUID4 regex to avoid guessable tokens
JOB_ID_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
)
MAX_PCAP_BYTES = 100 * 1024 * 1024
VALID_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # PCAP LE (us)
    b"\xa1\xb2\xc3\xd4",  # PCAP BE (us)
    b"\x4d\x3c\xb2\xa1",  # PCAP LE (ns)
    b"\xa1\xb2\x3c\x4d",  # PCAP BE (ns)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
}

# S12: Bound max concurrent WebSocket clients
MAX_WS_CLIENTS = 16

# S5: Limit concurrent PCAP analysis runs to prevent DoS
ANALYZE_SEMAPHORE = asyncio.Semaphore(1)

# Global singletons
db = Database(DB_PATH)
cache = FlowCache(db=db)
tcp_client = TcpIngestClient(ENGINE_HOST, ENGINE_PORT, cache)

start_time = time.time()
active_websockets: Set[WebSocket] = set()


def verify_auth(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> None:
    """Verify shared token on sensitive endpoints if NETSIGHT_API_KEY is configured (S1)."""
    if not API_KEY or TESTING:
        return
    token = x_api_key if isinstance(x_api_key, str) else None
    if not token and isinstance(authorization, str):
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        else:
            token = authorization
    if not token or not hmac.compare_digest(token, API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")


async def _rollup_loop():
    """Background task that flushes 1-minute bucket rollups to SQLite."""
    while True:
        try:
            await asyncio.sleep(10.0)
            rollup = cache.harvest_minute_rollup()
            if rollup:
                db.record_minute_rollup(
                    minute_ts=rollup["minute_ts"],
                    total_bytes=rollup["total_bytes"],
                    total_packets=rollup["total_packets"],
                    bps=rollup["bps"],
                    pps=rollup["pps"],
                    active_flows=rollup["active_flows"],
                    app_data=rollup["app_data"],
                    domain_data=rollup.get("domain_data"),
                )
                logger.info(
                    f"Recorded 1-minute historical rollup for ts={rollup['minute_ts']}"
                )
            cache.prune_stale_closed_flows()
            db.prune_history(retention_days=7)

            # Clean up old output files (> 15 minutes)
            now_sec = time.time()
            for p in OUTPUT_DIR.glob("*_output.pcap"):
                try:
                    if now_sec - p.stat().st_mtime > 900:
                        p.unlink()
                except Exception:
                    pass
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in rollup loop: {e}")


async def _ws_broadcast_loop():
    """Broadcast real-time tick to all connected dashboard WebSockets."""
    while True:
        try:
            await asyncio.sleep(1.0)
            if not active_websockets:
                continue

            summary = cache.get_summary()
            recent_flows = cache.get_flows(limit=100)["flows"]
            recent_findings = cache.get_findings()[:50]

            payload = {
                "type": "tick",
                "summary": summary.model_dump(),
                "active_flows": [f.model_dump() for f in recent_flows],
                "stats": cache.latest_stats.model_dump(),
                "findings": [f.model_dump() for f in recent_findings],
            }
            message = json.dumps(payload)

            sockets = list(active_websockets)
            results = await asyncio.gather(
                *(asyncio.wait_for(ws.send_text(message), timeout=1.0) for ws in sockets),
                return_exceptions=True,
            )

            for ws, res in zip(sockets, results):
                if isinstance(res, Exception):
                    active_websockets.discard(ws)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"WS broadcast loop exception: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if (
        TESTING
        or "pytest" in sys.modules
        or os.getenv("PYTEST_CURRENT_TEST")
        or os.getenv("TESTING") == "1"
    ):
        yield
        return

    # Startup
    logger.info("Starting NetSight Collector...")
    tcp_client.start()
    rollup_task = asyncio.create_task(_rollup_loop())
    ws_task = asyncio.create_task(_ws_broadcast_loop())

    yield

    # Shutdown
    logger.info("Shutting down NetSight Collector...")
    rollup_task.cancel()
    ws_task.cancel()
    await tcp_client.stop()
    await asyncio.gather(rollup_task, ws_task, return_exceptions=True)


app = FastAPI(
    title="NetSight Telemetry API",
    version="1.0.0",
    description="Backend collector for NetSight DPI & Flow Monitoring",
    lifespan=lifespan,
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# REST Endpoints (thread-safe via FlowCache._lock)
# ============================================================================


@app.get("/api/health", response_model=HealthResponse)
def get_health():
    uptime = int(time.time() - start_time)
    return HealthResponse(
        status="ok",
        mode=cache.mode,
        engine_connected=cache.engine_connected,
        uptime_sec=uptime,
        active_flows=len(cache.flows),
        binary_found=True,
    )


@app.get("/api/summary", response_model=SummaryResponse, dependencies=[Depends(verify_auth)])
def get_summary():
    return cache.get_summary()


@app.get("/api/rates", response_model=List[RatePoint], dependencies=[Depends(verify_auth)])
def get_rates(seconds: Annotated[int, Query(ge=10, le=900)] = 900):
    """Seed the real-time throughput chart on initial page load (D5)."""
    return cache.get_rates(seconds=seconds)


@app.get("/api/flows", dependencies=[Depends(verify_auth)])
def get_flows(
    app: Optional[str] = None,
    domain: Optional[str] = None,
    ip: Optional[str] = None,
    proto: Optional[str] = None,
    state: Optional[str] = None,
    rule_match: Optional[bool] = None,
    quick_filter: Optional[str] = None,
    search: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
    sort_by: str = "bytes",
    order: str = "desc",
):
    return cache.get_flows(
        app=app,
        domain=domain,
        ip=ip,
        proto=proto,
        state=state,
        rule_match=rule_match,
        quick_filter=quick_filter,
        search=search,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        order=order,
    )


@app.get("/api/flows/{flow_id}", response_model=FlowRecord, dependencies=[Depends(verify_auth)])
def get_flow_by_id(flow_id: str):
    """Fetch single flow detail for the flow drawer directly (D1)."""
    flow = cache.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
    return flow


@app.get("/api/findings", response_model=List[Finding], dependencies=[Depends(verify_auth)])
def get_findings():
    """Retrieve all detected findings (rules, port scans, high-entropy DNS, uploads)."""
    return cache.get_findings()


@app.post("/api/findings/{finding_id}/acknowledge", dependencies=[Depends(verify_auth)])
def acknowledge_finding(finding_id: str):
    ok = cache.acknowledge_finding(finding_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"status": "ok", "acknowledged": True}


@app.get("/api/apps", response_model=List[AppBreakdown], dependencies=[Depends(verify_auth)])
def get_apps(minutes: Optional[int] = Query(default=None, ge=1, le=43200)):
    """Aggregate traffic volume by application, optionally over past N minutes (C1)."""
    return cache.get_apps(minutes=minutes)


@app.get("/api/domains", response_model=List[DomainBreakdown], dependencies=[Depends(verify_auth)])
def get_domains(minutes: Optional[int] = Query(default=None, ge=1, le=43200)):
    """Aggregate traffic volume by detected domain, optionally over past N minutes (C1)."""
    return cache.get_domains(minutes=minutes)


@app.get("/api/history", response_model=List[HistoryPoint], dependencies=[Depends(verify_auth)])
def get_history(minutes: Annotated[int, Query(ge=5, le=43200)] = 60):
    return db.get_history(minutes=minutes)


@app.get("/api/rules", response_model=RulesPayload, dependencies=[Depends(verify_auth)])
def get_rules():
    if not RULES_PATH.exists():
        return RulesPayload()
    try:
        content = RULES_PATH.read_text(encoding="utf-8")
        data = json.loads(content)
        return RulesPayload(**data)
    except Exception as e:
        logger.error(f"Error reading rules.json: {e}")
        return RulesPayload()


@app.put("/api/rules", dependencies=[Depends(verify_auth)])
def update_rules(payload: RulesPayload):
    try:
        content = payload.model_dump_json(indent=2)
        tmp_path = RULES_PATH.with_suffix(".json.tmp")
        tmp_path.write_text(content, encoding="utf-8")
        try:
            os.replace(tmp_path, RULES_PATH)
        except OSError:
            RULES_PATH.write_text(content, encoding="utf-8")
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
        logger.info(
            f"Updated rules.json with {len(payload.block_apps)} apps, {len(payload.block_domains)} domains, {len(payload.block_ips)} IPs, {len(payload.block_ports)} ports"
        )
        return {"status": "ok", "message": "Rules saved successfully"}
    except Exception as e:
        logger.error(f"Failed to write rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to write rules configuration")


@app.post("/api/analyze", dependencies=[Depends(verify_auth)])
async def analyze_pcap(
    file: UploadFile = File(...),
    block_apps: Optional[str] = Form(default=""),
    block_domains: Optional[str] = Form(default=""),
):
    """Batch offline PCAP analysis using netsight-engine --analyze (S5: concurrency capped)."""
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "Only .pcap and .pcapng files are supported")

    # S5: Single-flight concurrency limiter
    try:
        await asyncio.wait_for(ANALYZE_SEMAPHORE.acquire(), timeout=0.1)
    except asyncio.TimeoutError:
        raise HTTPException(429, "An analysis job is already in progress. Please try again later.")

    temp_input = tempfile.NamedTemporaryFile(suffix=".pcap", dir=str(UPLOAD_DIR), delete=False)
    input_path = Path(temp_input.name)
    job_id = str(uuid.uuid4())
    output_path = OUTPUT_DIR / f"{job_id}_output.pcap"
    rules_path = UPLOAD_DIR / f"{job_id}_rules.json"

    try:
        total_uploaded = 0
        header_bytes = b""
        try:
            while True:
                chunk = await file.read(65536)
                if not chunk:
                    break
                total_uploaded += len(chunk)
                if total_uploaded > MAX_PCAP_BYTES:
                    raise HTTPException(413, "File too large (max 100 MB)")
                if len(header_bytes) < 4:
                    header_bytes += chunk[:4 - len(header_bytes)]
                temp_input.write(chunk)
            temp_input.flush()
            temp_input.close()
        except HTTPException:
            temp_input.close()
            raise

        if total_uploaded < 24 or header_bytes[:4] not in VALID_PCAP_MAGICS:
            raise HTTPException(400, "Invalid PCAP/PCAPNG file header")

        try:
            if not ENGINE_BINARY.exists():
                logger.error(f"Engine binary missing at {ENGINE_BINARY}")
                raise HTTPException(500, "Engine analysis service is currently unavailable")

            # Build command line
            cmd = [str(ENGINE_BINARY), "--analyze", str(input_path), str(output_path)]

            # S23: Validate ad-hoc form fields with RulesPayload validators
            if block_apps or block_domains:
                raw_apps = (
                    [a.strip() for a in block_apps.split(",") if a.strip()]
                    if block_apps
                    else []
                )
                raw_domains = (
                    [d.strip() for d in block_domains.split(",") if d.strip()]
                    if block_domains
                    else []
                )
                try:
                    validated = RulesPayload(
                        block_apps=raw_apps, block_domains=raw_domains
                    )
                    apps_list = validated.block_apps
                    domains_list = validated.block_domains
                except ValueError as e:
                    raise HTTPException(400, f"Invalid rule parameter: {e}")
            else:
                apps_list = []
                domains_list = []

            if apps_list or domains_list:
                base_rules = {
                    "block_apps": [],
                    "block_domains": [],
                    "block_ips": [],
                    "block_ports": [],
                }
                if RULES_PATH.exists():
                    try:
                        base_rules = json.loads(RULES_PATH.read_text(encoding="utf-8"))
                    except Exception:
                        pass
                base_rules["block_apps"] = list(
                    set(base_rules.get("block_apps", []) + apps_list)
                )
                base_rules["block_domains"] = list(
                    set(base_rules.get("block_domains", []) + domains_list)
                )
                rules_path.write_text(json.dumps(base_rules, indent=2), encoding="utf-8")
                cmd.extend(["--rules", str(rules_path)])
            elif RULES_PATH.exists():
                cmd.extend(["--rules", str(RULES_PATH)])

            # Run with async timeout (30 seconds)
            t0 = time.perf_counter()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                raise HTTPException(504, "Analysis timed out after 30 seconds")

            duration_ms = round((time.perf_counter() - t0) * 1000, 1)

            if proc.returncode != 0:
                logger.error(f"Engine analyze error: {stderr_b.decode('utf-8', errors='replace')}")
                raise HTTPException(500, "Analysis failed during engine execution")

            # Extract JSON from stdout
            stdout_str = stdout_b.decode("utf-8", errors="replace")
            json_start = stdout_str.find("{")
            if json_start == -1:
                raise HTTPException(500, "Invalid engine output: No JSON found")

            analysis = json.loads(stdout_str[json_start:])
            summary_block = analysis.get("summary", {})
            raw_flows = analysis.get("top_flows", analysis.get("flows", []))

            normalized_flows = []
            blocked_flow_count = 0
            for f in raw_flows:
                src_ip, _, src_port = f.get("src", ":0").rpartition(":")
                dst_ip, _, dst_port = f.get("dst", ":0").rpartition(":")
                is_blocked = bool(f.get("blocked", False))
                if is_blocked:
                    blocked_flow_count += 1
                normalized_flows.append(
                    {
                        **f,
                        "src_ip": f.get("src_ip", src_ip),
                        "src_port": f.get(
                            "src_port", int(src_port) if src_port.isdigit() else 0
                        ),
                        "dst_ip": f.get("dst_ip", dst_ip),
                        "dst_port": f.get(
                            "dst_port", int(dst_port) if dst_port.isdigit() else 0
                        ),
                        "bytes_total": f.get("bytes", 0),
                        "packets_total": f.get("packets", 0),
                    }
                )

            # Aggregate stats from normalized_flows & summary_block
            total_bytes = summary_block.get(
                "total_bytes", sum(f.get("bytes_total", 0) for f in normalized_flows)
            )

            talkers_map: Dict[str, int] = {}
            apps_map: Dict[str, int] = {}
            domains_map: Dict[str, int] = {}
            for f in normalized_flows:
                src = f.get("src_ip", "")
                b = f.get("bytes_total", 0)
                if src:
                    talkers_map[src] = talkers_map.get(src, 0) + b
                app = f.get("app", "UNKNOWN")
                if app:
                    apps_map[app] = apps_map.get(app, 0) + b
                sni = f.get("sni", "")
                if sni:
                    domains_map[sni] = domains_map.get(sni, 0) + b

            top_talkers = [
                {"label": k, "bytes": v}
                for k, v in sorted(talkers_map.items(), key=lambda x: x[1], reverse=True)[:6]
            ]
            top_apps = [
                {"label": k, "bytes": v}
                for k, v in sorted(apps_map.items(), key=lambda x: x[1], reverse=True)[:6]
            ]
            top_domains = [
                {"label": k, "bytes": v}
                for k, v in sorted(domains_map.items(), key=lambda x: x[1], reverse=True)[:6]
            ]

            analysis["job_id"] = job_id
            analysis["filename"] = file.filename
            analysis["file_size"] = total_uploaded
            analysis["download_url"] = f"/api/analyze/download/{job_id}"
            analysis["total_packets"] = summary_block.get("total_packets", 0)
            analysis["total_flows"] = summary_block.get(
                "total_flows", len(normalized_flows)
            )
            analysis["unique_flows"] = analysis["total_flows"]
            analysis["total_bytes"] = total_bytes
            analysis["top_talkers"] = top_talkers
            analysis["top_apps"] = top_apps
            analysis["top_domains"] = top_domains
            analysis["blocked_flows"] = blocked_flow_count
            analysis["duration_ms"] = duration_ms
            analysis["flows"] = normalized_flows
            return JSONResponse(analysis)

        except subprocess.TimeoutExpired:
            raise HTTPException(504, "Analysis timed out (> 60 seconds)")
        finally:
            if input_path.exists():
                try:
                    input_path.unlink()
                except Exception:
                    pass
            if rules_path.exists():
                try:
                    rules_path.unlink()
                except Exception:
                    pass
    finally:
        ANALYZE_SEMAPHORE.release()


@app.get("/api/analyze/download/{job_id}", dependencies=[Depends(verify_auth)])
async def download_filtered_pcap(job_id: str):
    if not JOB_ID_RE.match(job_id):
        raise HTTPException(400, "Invalid job ID format")
    output_path = (OUTPUT_DIR / f"{job_id}_output.pcap").resolve()
    if output_path.parent != OUTPUT_DIR.resolve() or not output_path.exists():
        raise HTTPException(404, "Filtered PCAP not found")
    return FileResponse(
        path=str(output_path),
        media_type="application/vnd.tcpdump.pcap",
        filename=f"netsight_filtered_{job_id}.pcap",
    )


# ============================================================================
# WebSocket Endpoint
# ============================================================================


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    # S3: Origin header validation
    origin = websocket.headers.get("origin")
    if origin:
        norm_origin = origin.rstrip("/")
        allowed_origins = {o.rstrip("/") for o in CORS_ORIGINS}
        if norm_origin not in allowed_origins:
            logger.warning(f"Rejecting WebSocket from disallowed origin: {origin}")
            await websocket.close(code=1008)
            return

    # S1: Authentication check if API_KEY is configured
    if API_KEY and not TESTING:
        token = websocket.query_params.get("token") or websocket.headers.get("X-API-Key")
        if not token and "authorization" in websocket.headers:
            auth_hdr = websocket.headers["authorization"]
            parts = auth_hdr.split()
            token = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else auth_hdr
        if not token or not hmac.compare_digest(token, API_KEY):
            logger.warning("Rejecting unauthenticated WebSocket connection")
            await websocket.close(code=1008)
            return

    # S12: Bound max concurrent WebSocket clients
    if len(active_websockets) >= MAX_WS_CLIENTS:
        logger.warning(
            f"Max WebSocket clients ({MAX_WS_CLIENTS}) reached, rejecting connection"
        )
        await websocket.close(code=1013)
        return

    await websocket.accept()
    active_websockets.add(websocket)
    logger.info(f"WebSocket client connected. Total clients: {len(active_websockets)}")
    try:
        # Send immediate initial state
        initial_payload = {
            "type": "init",
            "summary": cache.get_summary().model_dump(),
            "active_flows": [
                f.model_dump() for f in cache.get_flows(limit=100)["flows"]
            ],
            "stats": cache.latest_stats.model_dump(),
            "findings": [f.model_dump() for f in cache.get_findings()[:50]],
        }
        await websocket.send_text(json.dumps(initial_payload))

        while True:
            # S12: Bounded receive text to prevent memory exhaustion
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if len(data) > 256:
                    logger.warning("Oversized WebSocket text frame received, dropping client")
                    await websocket.close(code=1009)
                    break
                if data.strip() == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                continue

    except WebSocketDisconnect:
        active_websockets.discard(websocket)
        logger.info(
            f"WebSocket client disconnected. Total clients: {len(active_websockets)}"
        )
    except Exception as e:
        active_websockets.discard(websocket)
        logger.debug(f"WebSocket error: {e}")


# Serve compiled dashboard frontend if available
_dashboard_dist = Path(__file__).resolve().parents[1] / "dashboard" / "dist"
if _dashboard_dist.exists() and (_dashboard_dist / "index.html").exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(_dashboard_dist), html=True), name="dashboard")


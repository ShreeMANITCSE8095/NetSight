"""Asyncio TCP client that ingests NDJSON records from the C++ engine."""

import asyncio
import json
import logging
from typing import Optional
from .models import FlowRecord, StatsRecord
from .flow_cache import FlowCache

logger = logging.getLogger(__name__)


class TcpIngestClient:
    def __init__(self, host: str, port: int, cache: FlowCache):
        self.host = host
        self.port = port
        self.cache = cache
        self.running = False
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self.running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info(f"Started TCP Ingest task for {self.host}:{self.port}")

    async def stop(self) -> None:
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.cache.engine_connected = False

    async def _run_loop(self) -> None:
        while self.running:
            writer = None
            try:
                logger.info(f"Connecting to NetSight Engine at {self.host}:{self.port}...")
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port, limit=1024 * 1024), timeout=1.0
                )
                self.cache.set_engine_connected(True)
                logger.info("Connected to NetSight C++ Engine.")

                while self.running:
                    try:
                        line = await reader.readline()
                    except (asyncio.LimitOverrunError, ValueError):
                        logger.warning("Engine ingest line exceeded size limit (1MB), skipping oversized chunk.")
                        try:
                            await reader.readuntil(b"\n")
                        except Exception:
                            pass
                        continue
                    if not line:
                        logger.warning("Engine connection closed (EOF).")
                        break

                    try:
                        text = line.decode("utf-8").strip()
                        if not text:
                            continue
                        data = json.loads(text)
                    except json.JSONDecodeError as jde:
                        logger.debug(f"Corrupted NDJSON line skipped: {jde}")
                        continue
                    except UnicodeDecodeError:
                        continue

                    try:
                        rec_type = data.get("type", "")

                        if rec_type in ("flow", "flow_end"):
                            flow = FlowRecord(**data)
                            if rec_type == "flow":
                                self.cache.update_flow(flow)
                            else:
                                self.cache.end_flow(flow)
                        elif rec_type == "stats":
                            if "mode" in data:
                                self.cache.mode = data["mode"]
                            stats = StatsRecord(**data)
                            self.cache.update_stats(stats)
                    except Exception as parse_err:
                        logger.debug(f"Error parsing NDJSON line: {parse_err}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.cache.set_engine_connected(False)
                logger.debug(f"Engine connection failed: {e}. Retrying in 1.5s...")
                await asyncio.sleep(1.5)
            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

        self.cache.set_engine_connected(False)

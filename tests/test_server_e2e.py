"""End-to-end test: spawn the real stdio MCP server and exchange JSON-RPC."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from tests.conftest import build_sample_db


@pytest.fixture
def sample_cache(tmp_path: Path) -> Path:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    build_sample_db(cache_dir / "bdu.sqlite")
    return cache_dir


class _StdioClient:
    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self._proc = proc
        self._request_id = 0

    async def send(self, method: str, params: dict | None = None) -> dict:
        self._request_id += 1
        msg = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params is not None:
            msg["params"] = params
        self._proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self._proc.stdin.drain()
        return await self._recv()

    async def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self._proc.stdin.drain()

    async def _recv(self) -> dict:
        line = await self._proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stream")
        return json.loads(line.decode())


async def _spawn(cache_dir: Path) -> tuple[asyncio.subprocess.Process, _StdioClient]:
    env = {
        **os.environ,
        "BDU_FSTEC_CACHE_DIR": str(cache_dir),
        "BDU_FSTEC_DB_URL": "http://127.0.0.1:0/unused",
        "BDU_FSTEC_STATS_URL": "http://127.0.0.1:0/unused",
    }
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "bdu_fstec_mcp._cli",
        "run",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    client = _StdioClient(proc)
    init = await client.send(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "bdu-fstec-mcp"
    await client.notify("notifications/initialized")
    return proc, client


async def _shutdown(proc: asyncio.subprocess.Process) -> None:
    if proc.stdin and not proc.stdin.is_closing():
        proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        proc.terminate()
        await proc.wait()


async def test_e2e_handshake_and_list_tools(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send("tools/list")
        names = {t["name"] for t in resp["result"]["tools"]}
        assert names == {
            "search_bdu_vulnerabilities",
            "get_bdu_vulnerability",
            "find_bdu_by_cve",
            "get_bdu_stats",
        }
    finally:
        await _shutdown(proc)


async def test_e2e_call_get_stats(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send(
            "tools/call", {"name": "get_bdu_stats", "arguments": {}}
        )
        text = resp["result"]["content"][0]["text"]
        assert "БДУ ФСТЭК" in text
        assert "Записей: 4" in text
    finally:
        await _shutdown(proc)


async def test_e2e_call_search_with_filters(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send(
            "tools/call",
            {
                "name": "search_bdu_vulnerabilities",
                "arguments": {
                    "query": "PostgreSQL",
                    "limit": 5,
                    "min_cvss": 9.0,
                },
            },
        )
        text = resp["result"]["content"][0]["text"]
        assert "BDU:2024-00001" in text
        assert "BDU:2024-00003" not in text  # CVSS 5.0
    finally:
        await _shutdown(proc)


async def test_e2e_call_find_by_cve(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send(
            "tools/call",
            {"name": "find_bdu_by_cve", "arguments": {"cve_id": "CVE-2024-1111"}},
        )
        text = resp["result"]["content"][0]["text"]
        assert "BDU:2024-00001" in text
        assert "BDU:2024-00003" in text
    finally:
        await _shutdown(proc)


async def test_e2e_call_get_vulnerability(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send(
            "tools/call",
            {
                "name": "get_bdu_vulnerability",
                "arguments": {"bdu_id": "BDU:2024-00002"},
            },
        )
        text = resp["result"]["content"][0]["text"]
        assert "ядра Astra Linux" in text
        assert "Решение: Патч 1.7.4" in text
    finally:
        await _shutdown(proc)

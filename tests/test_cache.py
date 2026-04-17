"""Cache-layer tests: download, unpack, staleness."""

from __future__ import annotations

import datetime as dt
import gzip
import json
from pathlib import Path

import httpx
import pytest
import respx

from bdu_fstec_mcp._config import Config
from bdu_fstec_mcp.cache import CacheManager, MirrorUnavailableError


def _make_config(tmp_path: Path, staleness_days: int = 30) -> Config:
    return Config(
        db_url="https://example.invalid/bdu.sqlite.gz",
        stats_url="https://example.invalid/stats.json",
        cache_dir=tmp_path / "cache",
        staleness_days=staleness_days,
        request_timeout=5.0,
    )


@respx.mock
async def test_ensure_downloads_and_unpacks(tmp_path: Path):
    cfg = _make_config(tmp_path)
    respx.get(cfg.db_url).respond(
        content=gzip.compress(b"FAKE-SQLITE-CONTENT"),
        headers={"content-type": "application/gzip"},
    )
    respx.get(cfg.stats_url).respond(
        json={"snapshot_date": "2026-04-18"}
    )
    cache = CacheManager(cfg)
    try:
        db_path = await cache.ensure()
    finally:
        await cache.aclose()
    assert db_path.read_bytes() == b"FAKE-SQLITE-CONTENT"
    assert cache.stats_path.exists()


@respx.mock
async def test_ensure_reuses_cache_when_fresh(tmp_path: Path):
    cfg = _make_config(tmp_path)
    cfg.cache_dir.mkdir(parents=True)
    cache = CacheManager(cfg)
    cache.db_path.write_bytes(b"cached-data")
    # no respx route registered — if the code tried to hit the network it fails
    try:
        db_path = await cache.ensure()
    finally:
        await cache.aclose()
    assert db_path.read_bytes() == b"cached-data"


@respx.mock
async def test_ensure_force_redownloads(tmp_path: Path):
    cfg = _make_config(tmp_path)
    cfg.cache_dir.mkdir(parents=True)
    cache = CacheManager(cfg)
    cache.db_path.write_bytes(b"stale")
    respx.get(cfg.db_url).respond(content=gzip.compress(b"fresh"))
    respx.get(cfg.stats_url).respond(json={"snapshot_date": "2026-04-18"})
    try:
        await cache.ensure(force=True)
    finally:
        await cache.aclose()
    assert cache.db_path.read_bytes() == b"fresh"


@respx.mock
async def test_ensure_raises_when_mirror_unreachable_and_no_cache(tmp_path: Path):
    cfg = _make_config(tmp_path)
    respx.get(cfg.db_url).mock(side_effect=httpx.ConnectError("boom"))
    cache = CacheManager(cfg)
    try:
        with pytest.raises(MirrorUnavailableError):
            await cache.ensure()
    finally:
        await cache.aclose()


@respx.mock
async def test_ensure_falls_back_to_existing_cache_on_error(tmp_path: Path):
    cfg = _make_config(tmp_path)
    cfg.cache_dir.mkdir(parents=True)
    cache = CacheManager(cfg)
    cache.db_path.write_bytes(b"existing")
    respx.get(cfg.db_url).mock(side_effect=httpx.ConnectError("boom"))
    try:
        path = await cache.ensure(force=True)
    finally:
        await cache.aclose()
    # force=True triggered download, failed, fell back to existing cache
    assert path.read_bytes() == b"existing"


@respx.mock
async def test_staleness_remote_newer(tmp_path: Path):
    cfg = _make_config(tmp_path)
    respx.get(cfg.stats_url).respond(json={"snapshot_date": "2026-05-01"})
    cache = CacheManager(cfg)
    try:
        stale, reason = await cache.staleness_check("2026-04-01")
    finally:
        await cache.aclose()
    assert stale is True
    assert "более свежий" in reason


@respx.mock
async def test_staleness_age_threshold(tmp_path: Path):
    cfg = _make_config(tmp_path, staleness_days=7)
    respx.get(cfg.stats_url).mock(side_effect=httpx.TimeoutException("no"))
    cache = CacheManager(cfg)
    try:
        old = (dt.date.today() - dt.timedelta(days=30)).isoformat()
        stale, reason = await cache.staleness_check(old)
    finally:
        await cache.aclose()
    assert stale is True
    assert "старше" in reason


@respx.mock
async def test_staleness_fresh(tmp_path: Path):
    cfg = _make_config(tmp_path, staleness_days=30)
    today = dt.date.today().isoformat()
    respx.get(cfg.stats_url).respond(json={"snapshot_date": today})
    cache = CacheManager(cfg)
    try:
        stale, reason = await cache.staleness_check(today)
    finally:
        await cache.aclose()
    assert stale is False
    assert reason == ""


async def test_staleness_bad_local_date(tmp_path: Path):
    cfg = _make_config(tmp_path)
    cache = CacheManager(cfg)
    try:
        stale, reason = await cache.staleness_check("not-a-date")
    finally:
        await cache.aclose()
    assert stale is True
    assert "разобрать" in reason

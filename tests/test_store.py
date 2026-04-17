"""Store layer: FTS5 search, filters, lookup, snapshot info."""

from __future__ import annotations

from pathlib import Path

import pytest

from bdu_fstec_mcp.models import Vulnerability
from bdu_fstec_mcp.store import Store, _escape_fts_query


async def _make_store(path: Path) -> Store:
    store = Store(path)
    store.open()
    return store


async def test_fts_search_returns_ranked(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("PostgreSQL", limit=5)
    finally:
        store.close()
    ids = [v.id for v in results]
    assert len(results) == 2
    assert set(ids) == {"BDU:2024-00001", "BDU:2024-00003"}


async def test_empty_query_returns_cvss_sorted(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=2)
    finally:
        store.close()
    assert results[0].id == "BDU:2024-00001"  # CVSS 9.8 first
    assert results[1].id == "BDU:2024-00002"  # CVSS 8.1 second


async def test_min_cvss_filter(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=10, min_cvss=7.0)
    finally:
        store.close()
    scores = [v.cvss_score for v in results]
    assert all(s is not None and s >= 7.0 for s in scores)
    assert "BDU:2024-00003" not in {v.id for v in results}  # 5.0


async def test_min_severity_filter(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=10, min_severity=3)
    finally:
        store.close()
    assert {v.id for v in results} == {
        "BDU:2024-00001",
        "BDU:2024-00002",
        "BDU:2023-09999",
    }


async def test_year_filter(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=10, year=2023)
    finally:
        store.close()
    assert [v.id for v in results] == ["BDU:2023-09999"]


async def test_vendor_filter(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=10, vendor="Астра")
    finally:
        store.close()
    assert [v.id for v in results] == ["BDU:2024-00002"]


async def test_has_exploit_filter(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=10, has_exploit=True)
    finally:
        store.close()
    ids = {v.id for v in results}
    assert "BDU:2024-00001" in ids
    assert "BDU:2023-09999" in ids
    assert "BDU:2024-00002" not in ids  # exploit отсутствует


async def test_get_by_id_normalizes(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        v = await store.get("bdu:2024-00001")
        assert v is not None
        assert v.id == "BDU:2024-00001"
        assert v.cves == ("CVE-2024-1111",)
        assert v.software[0].vendor.startswith("PostgreSQL")
    finally:
        store.close()


async def test_get_missing_returns_none(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        assert await store.get("BDU:9999-99999") is None
    finally:
        store.close()


async def test_find_by_cve_reverse_mapping(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.find_by_cve("cve-2024-1111")
    finally:
        store.close()
    assert len(results) == 2
    assert all(isinstance(v, Vulnerability) for v in results)


async def test_find_by_cve_no_match(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        assert await store.find_by_cve("CVE-9999-0000") == []
    finally:
        store.close()


async def test_snapshot_info(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        info = await store.snapshot_info()
    finally:
        store.close()
    assert info.total == 4
    assert info.first_id == "BDU:2023-09999"
    assert info.last_id == "BDU:2024-00003"
    assert info.latest_update == "20.03.2024"
    assert info.snapshot_date == "2026-04-18"


async def test_search_limit_clamped_high(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=10_000)
    finally:
        store.close()
    assert len(results) == 4  # all we have


async def test_search_limit_clamped_low(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=0)  # clamped to 1
    finally:
        store.close()
    assert len(results) == 1


async def test_fts_escape_handles_injection():
    # Reserved words remain quoted (exact match, never operator).
    assert _escape_fts_query('OR "dangerous') == '"OR" dangerous*'
    assert _escape_fts_query("foo*bar AND baz") == 'foo* bar* "AND" baz*'
    assert _escape_fts_query("") == ""


async def test_fts_escape_cyrillic_trims_suffix():
    # Long Cyrillic word (≥6) → last 2 chars dropped for inflection tolerance.
    # "инъекция" (len 8) → "инъекц*" (matches инъекция, инъекции, …).
    assert _escape_fts_query("инъекция") == "инъекц*"
    assert _escape_fts_query("удалённое выполнение") == "удалённ* выполнен*"


async def test_fts_escape_short_cyrillic_kept_as_prefix():
    # Words too short to afford suffix trimming → plain prefix (≥3 chars).
    assert _escape_fts_query("код") == "код*"


async def test_fts_escape_splits_hyphenated_ids():
    # Hyphens/underscores are separators for FTS5's unicode61 tokenizer,
    # so matching any CVE or package name must decompose the identifier.
    assert _escape_fts_query("CVE-2024-1086") == "CVE* 2024* 1086*"
    assert _escape_fts_query("nft_verdict_init") == "nft* verdict* init*"


async def test_cyrillic_fts_tokenization(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("инъекция", limit=5)
    finally:
        store.close()
    assert any(v.id == "BDU:2024-00001" for v in results)


async def test_combined_filters(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search(
            "",
            limit=10,
            min_cvss=7.0,
            year=2024,
            has_exploit=True,
        )
    finally:
        store.close()
    assert {v.id for v in results} == {"BDU:2024-00001"}


async def test_fts_snippet_populated(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("PostgreSQL", limit=3)
    finally:
        store.close()
    assert results, "expected FTS hits"
    assert any("«" in v.match_snippet and "»" in v.match_snippet for v in results)


async def test_empty_query_has_no_snippet(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search("", limit=2)
    finally:
        store.close()
    assert all(v.match_snippet == "" for v in results)

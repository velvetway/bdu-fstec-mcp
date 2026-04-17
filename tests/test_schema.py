"""Schema-version sanity checks."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from bdu_fstec_mcp.store import SchemaVersionMismatch, Store


def _write_bare_db(path: Path, schema_version: str | None) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
    if schema_version is not None:
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES ('schema_version', ?)",
            (schema_version,),
        )
    conn.commit()
    conn.close()


def test_schema_version_mismatch_raises(tmp_path: Path):
    path = tmp_path / "bad.sqlite"
    _write_bare_db(path, schema_version="1")
    store = Store(path)
    with pytest.raises(SchemaVersionMismatch) as exc:
        store.open()
    assert "schema_version='1'" in str(exc.value)


def test_missing_schema_version_raises(tmp_path: Path):
    path = tmp_path / "nometa.sqlite"
    _write_bare_db(path, schema_version=None)
    store = Store(path)
    with pytest.raises(SchemaVersionMismatch):
        store.open()


def test_current_sample_db_opens(sample_db: Path):
    store = Store(sample_db)
    store.open()
    try:
        assert store._conn is not None
    finally:
        store.close()

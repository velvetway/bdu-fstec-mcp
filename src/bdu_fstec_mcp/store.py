"""SQLite store over the БДУ snapshot.

All heavy I/O is delegated to a single worker thread (``anyio.to_thread``)
so the stdio event loop stays non-blocking even while SQLite queries run.
"""

from __future__ import annotations

import datetime as dt
import re
import sqlite3
from pathlib import Path
from typing import Iterable

import anyio

from ._config import DEFAULT_BDU_PAGE_URL
from .models import SnapshotInfo, Software, Vulnerability


FTS_SAFE_CHARS = re.compile(r"[^0-9a-zA-Zа-яА-ЯёЁ\s\-_.]")


def _escape_fts_query(query: str) -> str:
    """Produce a safe FTS5 MATCH expression from arbitrary user input.

    Every token is wrapped in double quotes so FTS5 metacharacters (``AND``,
    ``OR``, ``NOT``, ``*``, ``"``) lose their special meaning. Multi-word
    queries become an implicit AND: ``Astra Linux`` → ``"astra" "linux"``.
    """
    cleaned = FTS_SAFE_CHARS.sub(" ", query)
    tokens = [t for t in cleaned.split() if t]
    if not tokens:
        return ""
    return " ".join(f'"{t}"' for t in tokens)


class Store:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        if self._conn is not None:
            return
        conn = sqlite3.connect(self._db_path, check_same_thread=False, uri=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = 1")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA mmap_size = 268435456")  # 256 MB mmap
        self._conn = conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ---- thread-safe public API --------------------------------------

    async def search(
        self,
        query: str,
        limit: int = 10,
        min_cvss: float | None = None,
        min_severity: int | None = None,
        year: int | None = None,
        vendor: str | None = None,
        has_exploit: bool | None = None,
    ) -> list[Vulnerability]:
        return await anyio.to_thread.run_sync(
            self._search_sync,
            query,
            limit,
            min_cvss,
            min_severity,
            year,
            vendor,
            has_exploit,
        )

    async def get(self, bdu_id: str) -> Vulnerability | None:
        return await anyio.to_thread.run_sync(self._get_sync, bdu_id)

    async def find_by_cve(self, cve_id: str) -> list[Vulnerability]:
        return await anyio.to_thread.run_sync(self._find_by_cve_sync, cve_id)

    async def snapshot_info(
        self,
        is_stale: bool = False,
        stale_reason: str = "",
    ) -> SnapshotInfo:
        return await anyio.to_thread.run_sync(
            self._snapshot_info_sync, is_stale, stale_reason
        )

    # ---- sync implementations (run in worker thread) -----------------

    def _conn_or_open(self) -> sqlite3.Connection:
        if self._conn is None:
            self.open()
        assert self._conn is not None
        return self._conn

    def _search_sync(
        self,
        query: str,
        limit: int,
        min_cvss: float | None,
        min_severity: int | None,
        year: int | None,
        vendor: str | None,
        has_exploit: bool | None,
    ) -> list[Vulnerability]:
        conn = self._conn_or_open()
        limit = max(1, min(limit, 100))

        match = _escape_fts_query(query) if query else ""
        params: list[object] = []
        filters: list[str] = []

        if match:
            sql = (
                "SELECT v.rowid AS rowid FROM vulnerabilities_fts f "
                "JOIN vulnerabilities v ON v.rowid = f.rowid "
                "WHERE vulnerabilities_fts MATCH ?"
            )
            params.append(match)
            order = "ORDER BY rank"
        else:
            sql = "SELECT v.rowid AS rowid FROM vulnerabilities v WHERE 1=1"
            order = "ORDER BY v.cvss_score DESC"

        if min_cvss is not None:
            filters.append("v.cvss_score >= ?")
            params.append(float(min_cvss))
        if min_severity is not None:
            filters.append("v.severity_level >= ?")
            params.append(int(min_severity))
        if year is not None:
            filters.append("v.identify_year = ?")
            params.append(int(year))
        if vendor:
            filters.append(
                "EXISTS (SELECT 1 FROM software s WHERE s.bdu_id = v.id "
                "AND s.vendor LIKE ? COLLATE NOCASE)"
            )
            params.append(f"%{vendor}%")
        if has_exploit is True:
            filters.append("v.has_exploit = 1")
        elif has_exploit is False:
            filters.append("v.has_exploit = 0")

        if filters:
            sql += " AND " + " AND ".join(filters)

        sql += f" {order} LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        if not rows:
            return []
        rowids = [r["rowid"] for r in rows]
        return self._hydrate(conn, rowids, preserve_order=True)

    def _get_sync(self, bdu_id: str) -> Vulnerability | None:
        conn = self._conn_or_open()
        key = self._normalize_id(bdu_id)
        row = conn.execute(
            "SELECT rowid FROM vulnerabilities WHERE id = ?",
            (key,),
        ).fetchone()
        if not row:
            return None
        results = self._hydrate(conn, [row["rowid"]])
        return results[0] if results else None

    def _find_by_cve_sync(self, cve_id: str) -> list[Vulnerability]:
        conn = self._conn_or_open()
        rows = conn.execute(
            "SELECT v.rowid AS rowid FROM cves c "
            "JOIN vulnerabilities v ON v.id = c.bdu_id "
            "WHERE c.cve_id = ? ORDER BY v.id",
            (cve_id.strip().upper(),),
        ).fetchall()
        rowids = [r["rowid"] for r in rows]
        return self._hydrate(conn, rowids, preserve_order=True)

    def _snapshot_info_sync(
        self, is_stale: bool, stale_reason: str
    ) -> SnapshotInfo:
        conn = self._conn_or_open()
        meta = dict(conn.execute("SELECT key, value FROM metadata").fetchall())
        first = conn.execute(
            "SELECT id FROM vulnerabilities ORDER BY id ASC LIMIT 1"
        ).fetchone()
        last = conn.execute(
            "SELECT id FROM vulnerabilities ORDER BY id DESC LIMIT 1"
        ).fetchone()
        latest_update = conn.execute(
            "SELECT last_upd_date FROM vulnerabilities "
            "WHERE last_upd_date != '' "
            "ORDER BY substr(last_upd_date,7,4) DESC, "
            "substr(last_upd_date,4,2) DESC, "
            "substr(last_upd_date,1,2) DESC LIMIT 1"
        ).fetchone()
        return SnapshotInfo(
            snapshot_date=meta.get("snapshot_date", ""),
            total=int(meta.get("total", "0") or 0),
            first_id=first["id"] if first else "",
            last_id=last["id"] if last else "",
            latest_update=latest_update["last_upd_date"] if latest_update else "",
            schema_version=meta.get("schema_version", ""),
            is_stale=is_stale,
            stale_reason=stale_reason,
        )

    # ---- hydration ---------------------------------------------------

    def _hydrate(
        self,
        conn: sqlite3.Connection,
        rowids: Iterable[int],
        preserve_order: bool = False,
    ) -> list[Vulnerability]:
        rowids = list(rowids)
        if not rowids:
            return []
        placeholders = ",".join("?" * len(rowids))
        rows = conn.execute(
            f"SELECT * FROM vulnerabilities WHERE rowid IN ({placeholders})",
            rowids,
        ).fetchall()
        by_rowid = {r["rowid"]: r for r in rows}
        ordered = [by_rowid[r] for r in rowids if r in by_rowid] if preserve_order else rows

        ids = tuple(r["id"] for r in ordered)
        cves_map = self._fetch_related(
            conn,
            "SELECT bdu_id, cve_id FROM cves WHERE bdu_id IN ({q}) ORDER BY cve_id",
            ids,
        )
        cwes_map = self._fetch_related(
            conn,
            "SELECT bdu_id, cwe_id FROM cwes WHERE bdu_id IN ({q}) ORDER BY cwe_id",
            ids,
        )
        software_map = self._fetch_software(conn, ids)

        vulns: list[Vulnerability] = []
        for row in ordered:
            bdu_id = row["id"]
            vulns.append(
                Vulnerability(
                    id=bdu_id,
                    name=row["name"] or "",
                    description=row["description"] or "",
                    severity=row["severity"] or "",
                    severity_level=int(row["severity_level"] or 0),
                    cvss_score=row["cvss_score"],
                    cvss_vector=row["cvss_vector"] or "",
                    identify_date=row["identify_date"] or "",
                    publication_date=row["publication_date"] or "",
                    last_upd_date=row["last_upd_date"] or "",
                    identify_year=row["identify_year"],
                    solution=row["solution"] or "",
                    status=row["status"] or "",
                    exploit_status=row["exploit_status"] or "",
                    fix_status=row["fix_status"] or "",
                    has_exploit=bool(row["has_exploit"]),
                    has_fix=bool(row["has_fix"]),
                    sources=row["sources"] or "",
                    url=DEFAULT_BDU_PAGE_URL.format(id=bdu_id),
                    cves=tuple(cves_map.get(bdu_id, [])),
                    cwes=tuple(cwes_map.get(bdu_id, [])),
                    software=tuple(software_map.get(bdu_id, [])),
                )
            )
        return vulns

    @staticmethod
    def _fetch_related(
        conn: sqlite3.Connection, sql: str, ids: tuple[str, ...]
    ) -> dict[str, list[str]]:
        if not ids:
            return {}
        placeholders = ",".join("?" * len(ids))
        rows = conn.execute(sql.format(q=placeholders), ids).fetchall()
        out: dict[str, list[str]] = {}
        for r in rows:
            out.setdefault(r[0], []).append(r[1])
        return out

    @staticmethod
    def _fetch_software(
        conn: sqlite3.Connection, ids: tuple[str, ...]
    ) -> dict[str, list[Software]]:
        if not ids:
            return {}
        placeholders = ",".join("?" * len(ids))
        rows = conn.execute(
            f"SELECT bdu_id, name, vendor, version FROM software "
            f"WHERE bdu_id IN ({placeholders})",
            ids,
        ).fetchall()
        out: dict[str, list[Software]] = {}
        for r in rows:
            out.setdefault(r["bdu_id"], []).append(
                Software(
                    name=r["name"] or "",
                    vendor=r["vendor"] or "",
                    version=r["version"] or "",
                )
            )
        return out

    @staticmethod
    def _normalize_id(raw: str) -> str:
        key = (raw or "").strip()
        if not key:
            return key
        up = key.upper()
        if up.startswith("BDU:"):
            return up
        if up.isdigit():
            return f"BDU:{up}"
        return up

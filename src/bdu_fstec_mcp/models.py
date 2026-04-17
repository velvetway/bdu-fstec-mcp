"""Value objects returned by the store."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Software:
    name: str
    vendor: str
    version: str


@dataclass(frozen=True)
class Vulnerability:
    id: str
    name: str
    description: str
    severity: str
    severity_level: int
    cvss_score: float | None
    cvss_vector: str
    identify_date: str
    publication_date: str
    last_upd_date: str
    identify_year: int | None
    solution: str
    status: str
    exploit_status: str
    fix_status: str
    has_exploit: bool
    has_fix: bool
    sources: str
    url: str
    cves: tuple[str, ...] = field(default_factory=tuple)
    cwes: tuple[str, ...] = field(default_factory=tuple)
    software: tuple[Software, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SnapshotInfo:
    """Details about the local cached snapshot of БДУ."""

    snapshot_date: str  # YYYY-MM-DD — date the mirror refreshed its copy
    total: int
    first_id: str
    last_id: str
    latest_update: str  # last <last_upd_date> across all records (source-side)
    schema_version: str
    is_stale: bool
    stale_reason: str  # human-readable diagnostic, empty if fresh

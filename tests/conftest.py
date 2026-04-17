"""Shared pytest fixtures — builds a tiny synthetic SQLite for unit tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


SAMPLE_VULS = [
    {
        "id": "BDU:2024-00001",
        "name": "Тестовая SQL-инъекция в PostgreSQL",
        "description": "SQL-инъекция через некорректную валидацию входных параметров.",
        "severity": "Критический уровень опасности",
        "severity_level": 4,
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "identify_date": "01.01.2024",
        "publication_date": "02.01.2024",
        "last_upd_date": "10.01.2024",
        "identify_year": 2024,
        "solution": "Обновление до PostgreSQL 16.1",
        "status": "Подтверждена производителем",
        "exploit_status": "Существует",
        "fix_status": "Имеется",
        "has_exploit": 1,
        "has_fix": 1,
        "sources": "nvd.nist.gov",
        "software": [("PostgreSQL", "PostgreSQL Global Development Group", "16.0")],
        "cves": ["CVE-2024-1111"],
        "cwes": ["CWE-89"],
    },
    {
        "id": "BDU:2024-00002",
        "name": "Уязвимость ядра Astra Linux SE",
        "description": "RCE через некорректную обработку модуля parsec.",
        "severity": "Высокий уровень опасности",
        "severity_level": 3,
        "cvss_score": 8.1,
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "identify_date": "05.02.2024",
        "publication_date": "06.02.2024",
        "last_upd_date": "15.02.2024",
        "identify_year": 2024,
        "solution": "Патч 1.7.4",
        "status": "Подтверждена производителем",
        "exploit_status": "Отсутствует",
        "fix_status": "Имеется",
        "has_exploit": 0,
        "has_fix": 1,
        "sources": "",
        "software": [("Astra Linux Special Edition", "ГК «Астра»", "1.7")],
        "cves": [],
        "cwes": [],
    },
    {
        "id": "BDU:2024-00003",
        "name": "Повторная уязвимость PostgreSQL",
        "description": "Уязвимость в PostgreSQL 15",
        "severity": "Средний уровень опасности",
        "severity_level": 2,
        "cvss_score": 5.0,
        "cvss_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:N",
        "identify_date": "10.03.2024",
        "publication_date": "11.03.2024",
        "last_upd_date": "20.03.2024",
        "identify_year": 2024,
        "solution": "",
        "status": "Потенциальная",
        "exploit_status": "Неизвестно",
        "fix_status": "Данные уточняются",
        "has_exploit": 0,
        "has_fix": 0,
        "sources": "",
        "software": [("PostgreSQL", "PostgreSQL Global Development Group", "15.0")],
        "cves": ["CVE-2024-1111"],
        "cwes": [],
    },
    {
        "id": "BDU:2023-09999",
        "name": "Старая уязвимость Windows",
        "description": "EoP в подсистеме печати Windows.",
        "severity": "Высокий уровень опасности",
        "severity_level": 3,
        "cvss_score": 7.8,
        "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "identify_date": "15.07.2023",
        "publication_date": "16.07.2023",
        "last_upd_date": "20.07.2023",
        "identify_year": 2023,
        "solution": "KB5028166",
        "status": "Подтверждена производителем",
        "exploit_status": "Существует",
        "fix_status": "Имеется",
        "has_exploit": 1,
        "has_fix": 1,
        "sources": "",
        "software": [("Windows", "Microsoft", "11")],
        "cves": ["CVE-2023-38180"],
        "cwes": [],
    },
]


SCHEMA = """
CREATE TABLE vulnerabilities (
    rowid            INTEGER PRIMARY KEY,
    id               TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    description      TEXT,
    software_names   TEXT,
    vendors          TEXT,
    cves_joined      TEXT,
    severity         TEXT,
    severity_level   INTEGER,
    cvss_score       REAL,
    cvss_vector      TEXT,
    identify_date    TEXT,
    publication_date TEXT,
    last_upd_date    TEXT,
    identify_year    INTEGER,
    solution         TEXT,
    status           TEXT,
    exploit_status   TEXT,
    fix_status       TEXT,
    has_exploit      INTEGER NOT NULL DEFAULT 0,
    has_fix          INTEGER NOT NULL DEFAULT 0,
    sources          TEXT
);
CREATE INDEX idx_vul_severity      ON vulnerabilities(severity_level);
CREATE INDEX idx_vul_cvss          ON vulnerabilities(cvss_score);
CREATE INDEX idx_vul_year          ON vulnerabilities(identify_year);
CREATE INDEX idx_vul_year_cvss     ON vulnerabilities(identify_year, cvss_score DESC);
CREATE INDEX idx_vul_severity_cvss ON vulnerabilities(severity_level, cvss_score DESC);
CREATE INDEX idx_vul_cvss_year     ON vulnerabilities(cvss_score DESC, identify_year);

CREATE TABLE cves (
    bdu_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (bdu_id, cve_id)
);
CREATE INDEX idx_cves_cve ON cves(cve_id);

CREATE TABLE software (
    bdu_id  TEXT NOT NULL,
    name    TEXT,
    vendor  TEXT,
    version TEXT
);
CREATE INDEX idx_software_vendor ON software(vendor COLLATE NOCASE);
CREATE INDEX idx_software_bdu    ON software(bdu_id);

CREATE TABLE cwes (
    bdu_id TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (bdu_id, cwe_id)
);

CREATE VIRTUAL TABLE vulnerabilities_fts USING fts5(
    name, description, software_names, vendors, cves_joined,
    content = 'vulnerabilities', content_rowid = 'rowid',
    tokenize = "unicode61 remove_diacritics 2"
);

CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
"""


def build_sample_db(path: Path, snapshot_date: str = "2026-04-18") -> None:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    for rowid, v in enumerate(SAMPLE_VULS, start=1):
        conn.execute(
            """INSERT INTO vulnerabilities
               (rowid, id, name, description, software_names, vendors, cves_joined,
                severity, severity_level, cvss_score, cvss_vector,
                identify_date, publication_date, last_upd_date, identify_year,
                solution, status, exploit_status, fix_status, has_exploit, has_fix, sources)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rowid,
                v["id"],
                v["name"],
                v["description"],
                " ".join(s[0] for s in v["software"]),
                " ".join(s[1] for s in v["software"]),
                " ".join(v["cves"]),
                v["severity"],
                v["severity_level"],
                v["cvss_score"],
                v["cvss_vector"],
                v["identify_date"],
                v["publication_date"],
                v["last_upd_date"],
                v["identify_year"],
                v["solution"],
                v["status"],
                v["exploit_status"],
                v["fix_status"],
                v["has_exploit"],
                v["has_fix"],
                v["sources"],
            ),
        )
        for sn, sv, svv in v["software"]:
            conn.execute(
                "INSERT INTO software (bdu_id, name, vendor, version) VALUES (?,?,?,?)",
                (v["id"], sn, sv, svv),
            )
        for cve in v["cves"]:
            conn.execute(
                "INSERT OR IGNORE INTO cves(bdu_id, cve_id) VALUES (?,?)",
                (v["id"], cve),
            )
        for cwe in v["cwes"]:
            conn.execute(
                "INSERT OR IGNORE INTO cwes(bdu_id, cwe_id) VALUES (?,?)",
                (v["id"], cwe),
            )
    conn.execute("INSERT INTO vulnerabilities_fts(vulnerabilities_fts) VALUES('rebuild')")
    conn.execute("INSERT INTO metadata(key, value) VALUES ('snapshot_date', ?)", (snapshot_date,))
    conn.execute("INSERT INTO metadata(key, value) VALUES ('total', ?)", (str(len(SAMPLE_VULS)),))
    conn.execute("INSERT INTO metadata(key, value) VALUES ('schema_version', '3')")
    conn.commit()
    conn.close()


@pytest.fixture
def sample_db(tmp_path: Path) -> Path:
    path = tmp_path / "bdu.sqlite"
    build_sample_db(path)
    return path

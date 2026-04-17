"""Client that loads БДУ ФСТЭК snapshot from the mirror repository and
provides search/lookup helpers.

The dataset ships as a gzipped XML file (~28 MB, ~86 000 records). On first
use the client downloads it into a local cache directory and builds in-memory
indexes by BDU identifier, CVE id, and vendor name.
"""

from __future__ import annotations

import gzip
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

import httpx

MIRROR_URL = (
    "https://github.com/velvetway/bdu-fstec-mirror/raw/main/data/vulxml.xml.gz"
)
STATS_URL = (
    "https://raw.githubusercontent.com/velvetway/bdu-fstec-mirror/main/data/stats.json"
)
BDU_PAGE_URL = "https://bdu.fstec.ru/vul/{id}"

DEFAULT_CACHE_DIR = Path(
    os.environ.get("XDG_CACHE_HOME")
    or (Path.home() / ".cache")
) / "bdu-fstec-mcp"


def _text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _parse_vul(el: ET.Element) -> dict[str, Any]:
    identifier = _text(el.find("identifier"))
    cvss = el.find("cvss/vector")
    cvss_score = cvss.get("score") if cvss is not None else ""
    cvss_vector = _text(cvss)

    cves: list[str] = []
    for ident in el.findall("identifiers/identifier"):
        if ident.get("type", "").upper() == "CVE" and ident.text:
            cves.append(ident.text.strip())

    software: list[dict[str, str]] = []
    for soft in el.findall("vulnerable_software/soft"):
        software.append({
            "name": _text(soft.find("name")),
            "vendor": _text(soft.find("vendor")),
            "version": _text(soft.find("version")),
        })

    cwes: list[str] = []
    for cwe in el.findall("cwes/cwe/identifier"):
        if cwe.text:
            cwes.append(cwe.text.strip())

    return {
        "id": identifier,
        "name": _text(el.find("name")),
        "description": _text(el.find("description")),
        "severity": _text(el.find("severity")),
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cves": cves,
        "cwes": cwes,
        "software": software,
        "identify_date": _text(el.find("identify_date")),
        "publication_date": _text(el.find("publication_date")),
        "last_upd_date": _text(el.find("last_upd_date")),
        "solution": _text(el.find("solution")),
        "status": _text(el.find("vul_status")),
        "exploit_status": _text(el.find("exploit_status")),
        "fix_status": _text(el.find("fix_status")),
        "sources": _text(el.find("sources")),
        "url": BDU_PAGE_URL.format(id=identifier) if identifier else None,
    }


class BduClient:
    def __init__(
        self,
        cache_dir: Path | None = None,
        mirror_url: str = MIRROR_URL,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self._cache_file = self._cache_dir / "vulxml.xml.gz"
        self._mirror_url = mirror_url
        self._http = http_client
        self._owns_http = http_client is None
        self._vulns: list[dict[str, Any]] = []
        self._by_id: dict[str, dict[str, Any]] = {}
        self._by_cve: dict[str, list[dict[str, Any]]] = {}
        self._loaded = False

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=60.0, follow_redirects=True)
        return self._http

    async def _ensure_cache(self) -> Path:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        if self._cache_file.exists() and self._cache_file.stat().st_size > 0:
            return self._cache_file
        http = await self._get_http()
        resp = await http.get(self._mirror_url)
        resp.raise_for_status()
        self._cache_file.write_bytes(resp.content)
        return self._cache_file

    async def load(self, force: bool = False) -> None:
        if self._loaded and not force:
            return
        path = await self._ensure_cache()
        with gzip.open(path, "rb") as f:
            root = ET.parse(f).getroot()
        vulns: list[dict[str, Any]] = []
        by_id: dict[str, dict[str, Any]] = {}
        by_cve: dict[str, list[dict[str, Any]]] = {}
        for el in root.findall("vul"):
            vul = _parse_vul(el)
            if not vul["id"]:
                continue
            vulns.append(vul)
            by_id[vul["id"]] = vul
            for cve in vul["cves"]:
                by_cve.setdefault(cve.upper(), []).append(vul)
        self._vulns = vulns
        self._by_id = by_id
        self._by_cve = by_cve
        self._loaded = True

    @property
    def total(self) -> int:
        return len(self._vulns)

    async def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        await self.load()
        limit = max(1, min(limit, 100))
        if not query:
            return self._vulns[:limit]
        q = query.lower()
        matches: list[dict[str, Any]] = []
        for v in self._vulns:
            hay = " ".join(
                [
                    v["name"],
                    v["description"],
                    " ".join(s["name"] for s in v["software"]),
                    " ".join(s["vendor"] for s in v["software"]),
                ]
            ).lower()
            if q in hay:
                matches.append(v)
                if len(matches) >= limit:
                    break
        return matches

    async def get(self, bdu_id: str) -> dict[str, Any] | None:
        await self.load()
        key = bdu_id.strip()
        if not key.upper().startswith("BDU:") and key.isdigit():
            key = f"BDU:{key}"
        return self._by_id.get(key) or self._by_id.get(key.upper())

    async def find_by_cve(self, cve_id: str) -> list[dict[str, Any]]:
        await self.load()
        return list(self._by_cve.get(cve_id.strip().upper(), []))

    async def list_by_vendor(
        self, vendor: str, limit: int = 10
    ) -> list[dict[str, Any]]:
        await self.load()
        limit = max(1, min(limit, 100))
        needle = vendor.strip().lower()
        if not needle:
            return []
        matches: list[dict[str, Any]] = []
        for v in self._vulns:
            if any(needle in s["vendor"].lower() for s in v["software"]):
                matches.append(v)
                if len(matches) >= limit:
                    break
        return matches

    async def stats(self) -> dict[str, Any]:
        await self.load()
        ids: Iterable[str] = (v["id"] for v in self._vulns)
        first = min(ids, default="")
        last = max((v["id"] for v in self._vulns), default="")
        latest_update = max(
            (v["last_upd_date"] for v in self._vulns if v["last_upd_date"]),
            default="",
        )
        return {
            "total": self.total,
            "first_id": first,
            "last_id": last,
            "latest_update": latest_update,
            "mirror": self._mirror_url,
        }

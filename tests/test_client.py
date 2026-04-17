"""Tests for BduClient: parsing, indexing, search, lookup."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from bdu_fstec_mcp.client import BduClient, _parse_vul


SAMPLE_XML = """<?xml version="1.0" encoding="utf-8"?>
<vulnerabilities>
  <vul>
    <identifier>BDU:2024-00001</identifier>
    <name>Тестовая уязвимость SQL-инъекции</name>
    <description>Описание уязвимости в PostgreSQL</description>
    <vulnerable_software>
      <soft>
        <name>PostgreSQL</name>
        <vendor>PostgreSQL Global Development Group</vendor>
        <version>16.0</version>
      </soft>
    </vulnerable_software>
    <cwes><cwe><identifier>CWE-89</identifier><name>SQL Injection</name></cwe></cwes>
    <identify_date>01.01.2024</identify_date>
    <publication_date>02.01.2024</publication_date>
    <last_upd_date>10.01.2024</last_upd_date>
    <cvss><vector score="9.8">AV:N/AC:L/Au:N/C:C/I:C/A:C</vector></cvss>
    <severity>Критический уровень опасности</severity>
    <solution>Обновление до 16.1</solution>
    <vul_status>Подтверждена производителем</vul_status>
    <exploit_status>Существует</exploit_status>
    <fix_status>Имеется</fix_status>
    <identifiers>
      <identifier type="CVE" link="https://nvd.nist.gov/vuln/detail/CVE-2024-1111">CVE-2024-1111</identifier>
    </identifiers>
  </vul>
  <vul>
    <identifier>BDU:2024-00002</identifier>
    <name>Уязвимость удалённого выполнения кода в Astra Linux</name>
    <description>RCE в ядре Astra Linux Special Edition</description>
    <vulnerable_software>
      <soft>
        <name>Astra Linux Special Edition</name>
        <vendor>ГК «Астра»</vendor>
        <version>1.7</version>
      </soft>
    </vulnerable_software>
    <cwes/>
    <identify_date>05.02.2024</identify_date>
    <publication_date>06.02.2024</publication_date>
    <last_upd_date>15.02.2024</last_upd_date>
    <cvss><vector score="8.1">AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</vector></cvss>
    <severity>Высокий уровень опасности</severity>
    <solution>Применить патч 1.7.4</solution>
    <vul_status>Подтверждена производителем</vul_status>
    <exploit_status>Отсутствует</exploit_status>
    <fix_status>Имеется</fix_status>
    <identifiers/>
  </vul>
  <vul>
    <identifier>BDU:2024-00003</identifier>
    <name>Повторная ссылка на CVE</name>
    <description>Другая уязвимость в PostgreSQL</description>
    <vulnerable_software>
      <soft>
        <name>PostgreSQL</name>
        <vendor>PostgreSQL Global Development Group</vendor>
        <version>15.0</version>
      </soft>
    </vulnerable_software>
    <cwes/>
    <identify_date>10.03.2024</identify_date>
    <publication_date>11.03.2024</publication_date>
    <last_upd_date>20.03.2024</last_upd_date>
    <cvss><vector score="5.0">AV:N/AC:L/Au:N/C:P/I:P/A:N</vector></cvss>
    <severity>Средний уровень опасности</severity>
    <solution></solution>
    <vul_status>Потенциальная</vul_status>
    <exploit_status>Неизвестно</exploit_status>
    <fix_status>Данные уточняются</fix_status>
    <identifiers>
      <identifier type="CVE">CVE-2024-1111</identifier>
    </identifiers>
  </vul>
</vulnerabilities>
"""


@pytest.fixture
def sample_cache(tmp_path: Path) -> Path:
    cache_file = tmp_path / "vulxml.xml.gz"
    with gzip.open(cache_file, "wb") as f:
        f.write(SAMPLE_XML.encode("utf-8"))
    return cache_file


@pytest.fixture
async def client(tmp_path: Path, sample_cache: Path) -> BduClient:
    c = BduClient(cache_dir=tmp_path)
    # cache already in place, load skips download
    yield c
    await c.aclose()


async def test_parse_vul_extracts_fields():
    import xml.etree.ElementTree as ET
    root = ET.fromstring(SAMPLE_XML)
    vul = _parse_vul(root.find("vul"))
    assert vul["id"] == "BDU:2024-00001"
    assert "SQL-инъекции" in vul["name"]
    assert vul["cves"] == ["CVE-2024-1111"]
    assert vul["cwes"] == ["CWE-89"]
    assert vul["cvss_score"] == "9.8"
    assert vul["software"][0]["vendor"].startswith("PostgreSQL")
    assert vul["url"] == "https://bdu.fstec.ru/vul/BDU:2024-00001"


async def test_load_builds_indexes(client: BduClient):
    await client.load()
    assert client.total == 3
    assert (await client.get("BDU:2024-00002"))["name"].startswith("Уязвимость удалённого")
    matches = await client.find_by_cve("CVE-2024-1111")
    assert len(matches) == 2


async def test_search_finds_by_description(client: BduClient):
    results = await client.search("postgres", limit=5)
    assert len(results) == 2
    ids = {r["id"] for r in results}
    assert ids == {"BDU:2024-00001", "BDU:2024-00003"}


async def test_search_respects_limit(client: BduClient):
    results = await client.search("уязвимость", limit=1)
    assert len(results) == 1


async def test_search_clamps_limit(client: BduClient):
    results = await client.search("", limit=999)
    # with empty query, returns first N — 3 total, clamped safely
    assert len(results) == 3


async def test_list_by_vendor(client: BduClient):
    results = await client.list_by_vendor("Астра", limit=5)
    assert len(results) == 1
    assert results[0]["id"] == "BDU:2024-00002"


async def test_find_by_cve_case_insensitive(client: BduClient):
    results = await client.find_by_cve("cve-2024-1111")
    assert len(results) == 2


async def test_stats(client: BduClient):
    s = await client.stats()
    assert s["total"] == 3
    assert s["first_id"] == "BDU:2024-00001"
    assert s["last_id"] == "BDU:2024-00003"
    assert s["latest_update"] == "20.03.2024"


async def test_get_missing_returns_none(client: BduClient):
    assert await client.get("BDU:9999-99999") is None

"""Formatters produce the text blocks surfaced to the LLM."""

from __future__ import annotations

from bdu_fstec_mcp.formatters import (
    format_full,
    format_search_results,
    format_snapshot,
    format_short,
)
from bdu_fstec_mcp.models import SnapshotInfo, Software, Vulnerability


def _sample_vul(**overrides) -> Vulnerability:
    base = dict(
        id="BDU:2024-00001",
        name="Тестовая уязвимость",
        description="Описание",
        severity="Высокий уровень опасности",
        severity_level=3,
        cvss_score=7.5,
        cvss_vector="AV:N/AC:L",
        identify_date="01.01.2024",
        publication_date="02.01.2024",
        last_upd_date="10.01.2024",
        identify_year=2024,
        solution="Обновиться",
        status="Подтверждена производителем",
        exploit_status="Существует",
        fix_status="Имеется",
        has_exploit=True,
        has_fix=True,
        sources="ru-cert",
        url="https://bdu.fstec.ru/vul/BDU:2024-00001",
        cves=("CVE-2024-1234",),
        cwes=("CWE-89",),
        software=(Software(name="PostgreSQL", vendor="PostgreSQL GDG", version="16.0"),),
    )
    base.update(overrides)
    return Vulnerability(**base)


def test_short_includes_core_fields():
    text = format_short(_sample_vul())
    assert "BDU:2024-00001" in text
    assert "Высокий уровень опасности" in text
    assert "CVE-2024-1234" in text
    assert "PostgreSQL GDG PostgreSQL 16.0" in text
    assert "bdu.fstec.ru" in text


def test_short_truncates_long_description():
    text = format_short(_sample_vul(description="A" * 800))
    assert "…" in text
    assert len([l for l in text.split("\n") if "A" in l][0]) <= 420


def test_full_adds_solution_cwe_sources():
    text = format_full(_sample_vul())
    assert "Решение: Обновиться" in text
    assert "Эксплойт: Существует" in text
    assert "Исправление: Имеется" in text
    assert "CWE: CWE-89" in text
    assert "Источники: ru-cert" in text


def test_full_omits_empty_extras():
    vul = _sample_vul(solution="", exploit_status="", fix_status="", cwes=(), sources="")
    text = format_full(vul)
    assert "Решение:" not in text
    assert "Эксплойт:" not in text


def test_search_results_empty():
    assert (
        format_search_results([], "sql")
        == "Ничего не найдено по запросу «sql»."
    )


def test_search_results_with_filters_header():
    vul = _sample_vul()
    text = format_search_results([vul], "sql", "CVSS ≥ 7, год: 2024")
    assert "CVSS ≥ 7" in text
    assert "год: 2024" in text
    assert vul.id in text


def test_snapshot_fresh():
    info = SnapshotInfo(
        snapshot_date="2026-04-18",
        total=86664,
        first_id="BDU:2014-00001",
        last_id="BDU:2026-05547",
        latest_update="31.12.2025",
        schema_version="1",
        is_stale=False,
        stale_reason="",
    )
    text = format_snapshot(info)
    assert "Свежий" in text or "✓" in text
    assert "86664" in text
    assert "BDU:2014-00001 → BDU:2026-05547" in text


def test_snapshot_stale_surfaces_reason():
    info = SnapshotInfo(
        snapshot_date="2025-01-01",
        total=80000,
        first_id="a",
        last_id="b",
        latest_update="31.12.2024",
        schema_version="1",
        is_stale=True,
        stale_reason="Снимок старше 30 дней.",
    )
    assert "устарел" in format_snapshot(info)
    assert "Снимок старше 30 дней." in format_snapshot(info)


def test_short_shows_extra_software_count():
    vul = _sample_vul(
        software=tuple(
            Software(name=f"sw{i}", vendor=f"v{i}", version="1") for i in range(8)
        )
    )
    text = format_short(vul)
    assert "(+3)" in text  # 8 items, 5 shown

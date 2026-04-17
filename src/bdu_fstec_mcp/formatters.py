"""Pretty-printers that turn domain objects into text blocks for the LLM."""

from __future__ import annotations

from .models import SnapshotInfo, Vulnerability


_DESC_PREVIEW_LIMIT = 400


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "…"


def format_short(v: Vulnerability) -> str:
    """One-screen summary of a vulnerability — the search-result format."""
    lines = [f"{v.id} — {v.name}"]
    if v.severity:
        lines.append(f"  Опасность: {v.severity}")
    elif v.cvss_score is not None:
        lines.append(f"  CVSS: {v.cvss_score} ({v.cvss_vector})")
    if v.cves:
        lines.append(f"  CVE: {', '.join(v.cves)}")
    if v.software:
        preview = ", ".join(
            " ".join(part for part in (s.vendor, s.name, s.version) if part)
            for s in v.software[:5]
        )
        if len(v.software) > 5:
            preview += f" (+{len(v.software) - 5})"
        lines.append(f"  ПО: {preview}")
    if v.publication_date:
        lines.append(f"  Опубликована: {v.publication_date}")
    if v.status:
        lines.append(f"  Статус: {v.status}")
    lines.append(f"  {v.url}")
    if v.description:
        lines.append(f"  {_truncate(v.description, _DESC_PREVIEW_LIMIT)}")
    return "\n".join(lines)


def format_full(v: Vulnerability) -> str:
    """Full record including solution, CWEs, and source references."""
    parts = [format_short(v)]
    extras: list[str] = []
    if v.solution:
        extras.append(f"Решение: {v.solution}")
    if v.exploit_status:
        extras.append(f"Эксплойт: {v.exploit_status}")
    if v.fix_status:
        extras.append(f"Исправление: {v.fix_status}")
    if v.cwes:
        extras.append(f"CWE: {', '.join(v.cwes)}")
    if v.sources:
        extras.append(f"Источники: {v.sources}")
    if extras:
        parts.append("")
        parts.extend(extras)
    return "\n".join(parts)


def format_snapshot(info: SnapshotInfo) -> str:
    lines = [
        "БДУ ФСТЭК — снимок данных",
        f"  Записей: {info.total}",
        f"  Идентификаторы: {info.first_id} → {info.last_id}",
        f"  Дата снимка в зеркале: {info.snapshot_date}",
    ]
    if info.latest_update:
        lines.append(f"  Последнее обновление источника: {info.latest_update}")
    if info.is_stale:
        lines.append(f"  ⚠ Снимок устарел: {info.stale_reason}")
    else:
        lines.append("  ✓ Снимок свежий.")
    return "\n".join(lines)


def format_search_results(
    results: list[Vulnerability], query: str, total_filters: str = ""
) -> str:
    if not results:
        tail = f" ({total_filters})" if total_filters else ""
        return f"Ничего не найдено по запросу «{query}»{tail}."
    header = f"Найдено {len(results)} результатов по запросу «{query}»"
    if total_filters:
        header += f" ({total_filters})"
    body = "\n\n".join(format_short(v) for v in results)
    return f"{header}:\n\n{body}"

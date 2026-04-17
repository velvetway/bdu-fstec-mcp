"""MCP stdio server exposing БДУ ФСТЭК as a small set of tools."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from ._config import Config
from .cache import CacheManager
from .formatters import (
    format_full,
    format_search_results,
    format_snapshot,
    format_short,
)
from .store import Store


logger = logging.getLogger("bdu_fstec_mcp")


class BduServer:
    """Ties together config, cache, store, and the MCP protocol."""

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config.from_env()
        self._cache = CacheManager(self._config)
        self._store: Store | None = None
        self._stale_reason = ""
        self._is_stale = False
        self._ready = asyncio.Lock()

    async def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None
        await self._cache.aclose()

    async def _ensure_ready(self) -> Store:
        if self._store is not None:
            return self._store
        async with self._ready:
            if self._store is not None:
                return self._store
            db_path = await self._cache.ensure()
            store = Store(db_path)
            store.open()
            # staleness check is best-effort
            snap = await store.snapshot_info()
            try:
                is_stale, reason = await self._cache.staleness_check(
                    snap.snapshot_date
                )
                self._is_stale = is_stale
                self._stale_reason = reason
            except Exception as exc:  # pragma: no cover — best effort
                logger.debug("staleness check failed: %s", exc)
            self._store = store
            return store

    async def refresh(self) -> None:
        """Force re-download of the snapshot and reopen the store."""
        async with self._ready:
            if self._store is not None:
                self._store.close()
                self._store = None
            await self._cache.ensure(force=True)

    # ---- tool implementations --------------------------------------

    async def tool_search(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        query = (args.get("query") or "").strip()
        limit = int(args.get("limit", 10))
        filters_parts: list[str] = []

        min_cvss = args.get("min_cvss")
        if min_cvss is not None:
            filters_parts.append(f"CVSS ≥ {min_cvss}")
        min_severity = args.get("min_severity")
        if isinstance(min_severity, str):
            min_severity = {
                "низкий": 1,
                "средний": 2,
                "высокий": 3,
                "критический": 4,
            }.get(min_severity.lower())
        if min_severity is not None:
            severity_label = {1: "низкий", 2: "средний", 3: "высокий", 4: "критический"}.get(
                int(min_severity), str(min_severity)
            )
            filters_parts.append(f"опасность ≥ {severity_label}")
        year = args.get("year")
        if year is not None:
            filters_parts.append(f"год: {int(year)}")
        vendor = args.get("vendor") or None
        if vendor:
            filters_parts.append(f"вендор: {vendor}")
        has_exploit = args.get("has_exploit")
        if has_exploit is True:
            filters_parts.append("есть эксплойт")

        results = await store.search(
            query=query,
            limit=limit,
            min_cvss=float(min_cvss) if min_cvss is not None else None,
            min_severity=int(min_severity) if min_severity is not None else None,
            year=int(year) if year is not None else None,
            vendor=vendor,
            has_exploit=has_exploit if isinstance(has_exploit, bool) else None,
        )
        return format_search_results(results, query or "(без текстового запроса)", ", ".join(filters_parts))

    async def tool_get(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        bdu_id = (args.get("bdu_id") or "").strip()
        if not bdu_id:
            return "Укажите идентификатор BDU (например, BDU:2024-01234)."
        v = await store.get(bdu_id)
        if v is None:
            return f"Запись {bdu_id} не найдена в снимке."
        return format_full(v)

    async def tool_find_by_cve(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        cve_id = (args.get("cve_id") or "").strip()
        if not cve_id:
            return "Укажите идентификатор CVE (например, CVE-2024-1234)."
        results = await store.find_by_cve(cve_id)
        if not results:
            return f"В БДУ нет записей, ссылающихся на {cve_id.upper()}."
        header = f"Найдено {len(results)} записей БДУ для {cve_id.upper()}:\n\n"
        body = "\n\n".join(format_short(v) for v in results)
        return header + body

    async def tool_stats(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        info = await store.snapshot_info(
            is_stale=self._is_stale, stale_reason=self._stale_reason
        )
        return format_snapshot(info)


def _build_mcp_server(bdu: BduServer) -> Server:
    server: Server = Server("bdu-fstec-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="search_bdu_vulnerabilities",
                description=(
                    "Поиск по БДУ ФСТЭК с релевантностным ранжированием (FTS5). "
                    "Поддерживает полнотекстовый запрос и фильтры: CVSS, "
                    "уровень опасности, год обнаружения, вендор, наличие эксплойта."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": (
                                "Поисковая фраза (русский или английский). "
                                "Пример: «SQL injection», «Astra Linux», «OpenSSL heap»."
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Максимум результатов (1–100).",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100,
                        },
                        "min_cvss": {
                            "type": "number",
                            "description": "Минимальная оценка CVSS (0–10).",
                        },
                        "min_severity": {
                            "type": "string",
                            "description": "Минимальный уровень опасности.",
                            "enum": ["низкий", "средний", "высокий", "критический"],
                        },
                        "year": {
                            "type": "integer",
                            "description": "Год обнаружения уязвимости.",
                        },
                        "vendor": {
                            "type": "string",
                            "description": "Фрагмент имени вендора (подстрока).",
                        },
                        "has_exploit": {
                            "type": "boolean",
                            "description": "Только уязвимости с известным эксплойтом.",
                        },
                    },
                },
            ),
            Tool(
                name="get_bdu_vulnerability",
                description=(
                    "Полная запись по идентификатору БДУ (например, "
                    "BDU:2024-01234): CVSS, CVE, CWE, решение, эксплойт-статус."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "bdu_id": {
                            "type": "string",
                            "description": "Идентификатор БДУ, например 'BDU:2024-01234'.",
                        }
                    },
                    "required": ["bdu_id"],
                },
            ),
            Tool(
                name="find_bdu_by_cve",
                description=(
                    "Обратный маппинг CVE → БДУ. Находит российские записи, "
                    "ссылающиеся на указанный CVE-идентификатор."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": "Идентификатор CVE, например 'CVE-2024-1234'.",
                        }
                    },
                    "required": ["cve_id"],
                },
            ),
            Tool(
                name="get_bdu_stats",
                description=(
                    "Статистика текущего локального снимка БДУ и проверка "
                    "актуальности относительно зеркала."
                ),
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        try:
            if name == "search_bdu_vulnerabilities":
                text = await bdu.tool_search(arguments)
            elif name == "get_bdu_vulnerability":
                text = await bdu.tool_get(arguments)
            elif name == "find_bdu_by_cve":
                text = await bdu.tool_find_by_cve(arguments)
            elif name == "get_bdu_stats":
                text = await bdu.tool_stats(arguments)
            else:
                text = f"Неизвестный инструмент: {name}"
        except Exception as exc:
            logger.exception("tool %s failed", name)
            text = f"Ошибка при выполнении инструмента {name}: {exc}"
        return [TextContent(type="text", text=text)]

    return server


async def _run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    bdu = BduServer()
    try:
        mcp_server = _build_mcp_server(bdu)
        async with stdio_server() as (read, write):
            await mcp_server.run(read, write, mcp_server.create_initialization_options())
    finally:
        await bdu.close()


def main() -> None:
    # Delayed import avoids a circular reference: _cli imports from server.
    from ._cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()

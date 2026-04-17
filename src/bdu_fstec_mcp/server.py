"""Stdio MCP server exposing БДУ ФСТЭК vulnerability database as tools."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .client import BduClient

server: Server = Server("bdu-fstec-mcp")
_client: BduClient | None = None


def _get_client() -> BduClient:
    global _client
    if _client is None:
        _client = BduClient()
    return _client


def _format_vul(v: dict[str, Any]) -> str:
    lines: list[str] = [f"{v['id']} — {v['name']}"]
    if v.get("severity"):
        lines.append(f"  Опасность: {v['severity']}")
    elif v.get("cvss_score"):
        lines.append(f"  CVSS: {v['cvss_score']} ({v.get('cvss_vector', '')})")
    if v.get("cves"):
        lines.append(f"  CVE: {', '.join(v['cves'])}")
    if v.get("software"):
        soft = ", ".join(
            f"{s['vendor']} {s['name']} {s.get('version','')}".strip()
            for s in v["software"][:5]
        )
        lines.append(f"  ПО: {soft}")
    if v.get("publication_date"):
        lines.append(f"  Опубликована: {v['publication_date']}")
    if v.get("status"):
        lines.append(f"  Статус: {v['status']}")
    if v.get("url"):
        lines.append(f"  {v['url']}")
    if v.get("description"):
        desc = v["description"]
        if len(desc) > 400:
            desc = desc[:400] + "…"
        lines.append(f"  Описание: {desc}")
    return "\n".join(lines)


def _format_full(v: dict[str, Any]) -> str:
    parts = [_format_vul(v)]
    if v.get("solution"):
        parts.append(f"\n  Решение: {v['solution']}")
    if v.get("exploit_status"):
        parts.append(f"\n  Эксплойт: {v['exploit_status']}")
    if v.get("fix_status"):
        parts.append(f"\n  Исправление: {v['fix_status']}")
    if v.get("cwes"):
        parts.append(f"\n  CWE: {', '.join(v['cwes'])}")
    if v.get("sources"):
        parts.append(f"\n  Источники: {v['sources']}")
    return "".join(parts)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="search_bdu_vulnerabilities",
            description=(
                "Full-text search over БДУ ФСТЭК (Russian vulnerability database). "
                "Searches vulnerability name, description, and affected software. "
                "Returns up to 100 matching records."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search phrase in Russian or English (e.g. 'SQL injection', 'Astra Linux', 'OpenSSL').",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results (1-100).",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="get_bdu_vulnerability",
            description=(
                "Return a full record for a specific БДУ identifier "
                "(e.g. 'BDU:2024-01234'). Includes CVE mappings, CVSS, solution, "
                "exploit status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "bdu_id": {
                        "type": "string",
                        "description": "БДУ identifier, for example 'BDU:2024-01234'.",
                    },
                },
                "required": ["bdu_id"],
            },
        ),
        Tool(
            name="find_bdu_by_cve",
            description=(
                "Find БДУ ФСТЭК records that reference a given CVE identifier. "
                "Useful for cross-mapping international CVE → Russian БДУ."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE identifier, for example 'CVE-2024-1234'.",
                    },
                },
                "required": ["cve_id"],
            },
        ),
        Tool(
            name="list_bdu_by_vendor",
            description=(
                "List vulnerabilities affecting software from a given vendor. "
                "Matches against the vulnerable-software vendor field."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "vendor": {
                        "type": "string",
                        "description": "Vendor name, e.g. 'Positive Technologies', 'Astra Linux', 'Microsoft'.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results (1-100).",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100,
                    },
                },
                "required": ["vendor"],
            },
        ),
        Tool(
            name="get_bdu_stats",
            description="Return snapshot statistics: total vulnerabilities, id range, latest update.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    client = _get_client()

    if name == "search_bdu_vulnerabilities":
        query = (arguments.get("query") or "").strip()
        limit = int(arguments.get("limit", 10))
        results = await client.search(query, limit=limit)
        if not results:
            return [TextContent(type="text", text=f"Ничего не найдено по запросу «{query}».")]
        header = f"Найдено {len(results)} уязвимостей по запросу «{query}»:\n\n"
        body = "\n\n".join(_format_vul(v) for v in results)
        return [TextContent(type="text", text=header + body)]

    if name == "get_bdu_vulnerability":
        bdu_id = (arguments.get("bdu_id") or "").strip()
        v = await client.get(bdu_id)
        if not v:
            return [TextContent(type="text", text=f"Запись {bdu_id} не найдена.")]
        return [TextContent(type="text", text=_format_full(v))]

    if name == "find_bdu_by_cve":
        cve_id = (arguments.get("cve_id") or "").strip()
        results = await client.find_by_cve(cve_id)
        if not results:
            return [TextContent(type="text", text=f"В БДУ нет записей для {cve_id}.")]
        header = f"Найдено {len(results)} записей БДУ для {cve_id}:\n\n"
        body = "\n\n".join(_format_vul(v) for v in results)
        return [TextContent(type="text", text=header + body)]

    if name == "list_bdu_by_vendor":
        vendor = (arguments.get("vendor") or "").strip()
        limit = int(arguments.get("limit", 10))
        results = await client.list_by_vendor(vendor, limit=limit)
        if not results:
            return [TextContent(type="text", text=f"Не найдено уязвимостей для вендора «{vendor}».")]
        header = f"Найдено {len(results)} уязвимостей у вендора «{vendor}»:\n\n"
        body = "\n\n".join(_format_vul(v) for v in results)
        return [TextContent(type="text", text=header + body)]

    if name == "get_bdu_stats":
        s = await client.stats()
        text = (
            f"БДУ ФСТЭК, снимок из зеркала {s['mirror']}:\n"
            f"  Всего записей: {s['total']}\n"
            f"  Идентификаторы: {s['first_id']} → {s['last_id']}\n"
            f"  Последнее обновление источника: {s['latest_update']}"
        )
        return [TextContent(type="text", text=text)]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _run() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()

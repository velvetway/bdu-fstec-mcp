"""Entry-point CLI with subcommands: run (default), refresh, stats, version."""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from ._config import Config
from .cache import CacheManager, MirrorUnavailableError
from .formatters import format_snapshot
from .server import BduServer, _build_mcp_server
from mcp.server.stdio import stdio_server


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bdu-fstec-mcp",
        description="MCP-сервер для БДУ ФСТЭК (Russian vulnerability database).",
    )
    parser.add_argument("--version", action="version", version=f"bdu-fstec-mcp {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("run", help="Запустить MCP stdio-сервер (по умолчанию).")
    sub.add_parser("refresh", help="Принудительно перекачать снимок из зеркала.")
    sub.add_parser("stats", help="Показать метаданные локального снимка.")

    return parser.parse_args(argv)


async def _cmd_run() -> None:
    bdu = BduServer()
    try:
        mcp_server = _build_mcp_server(bdu)
        async with stdio_server() as (read, write):
            await mcp_server.run(read, write, mcp_server.create_initialization_options())
    finally:
        await bdu.close()


async def _cmd_refresh() -> None:
    cfg = Config.from_env()
    cache = CacheManager(cfg)
    try:
        path = await cache.ensure(force=True)
        print(f"Снимок обновлён: {path}")
    except MirrorUnavailableError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        await cache.aclose()


async def _cmd_stats() -> None:
    bdu = BduServer()
    try:
        print(await bdu.tool_stats({}))
    finally:
        await bdu.close()


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    cmd = args.command or "run"
    if cmd == "run":
        asyncio.run(_cmd_run())
    elif cmd == "refresh":
        asyncio.run(_cmd_refresh())
    elif cmd == "stats":
        asyncio.run(_cmd_stats())
    else:
        raise SystemExit(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()

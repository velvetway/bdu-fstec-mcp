"""Runtime configuration — env-var overridable."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


MIRROR_REPO = "velvetway/bdu-fstec-mirror"

DEFAULT_DB_URL = (
    f"https://github.com/{MIRROR_REPO}/raw/main/data/bdu.sqlite.gz"
)
DEFAULT_STATS_URL = (
    f"https://raw.githubusercontent.com/{MIRROR_REPO}/main/data/stats.json"
)
DEFAULT_BDU_PAGE_URL = "https://bdu.fstec.ru/vul/{id}"


def _default_cache_dir() -> Path:
    explicit = os.environ.get("BDU_FSTEC_CACHE_DIR")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "bdu-fstec-mcp"


@dataclass(frozen=True)
class Config:
    db_url: str
    stats_url: str
    cache_dir: Path
    staleness_days: int
    request_timeout: float

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            db_url=os.environ.get("BDU_FSTEC_DB_URL", DEFAULT_DB_URL),
            stats_url=os.environ.get("BDU_FSTEC_STATS_URL", DEFAULT_STATS_URL),
            cache_dir=_default_cache_dir(),
            staleness_days=int(os.environ.get("BDU_FSTEC_STALENESS_DAYS", "30")),
            request_timeout=float(
                os.environ.get("BDU_FSTEC_REQUEST_TIMEOUT", "120")
            ),
        )

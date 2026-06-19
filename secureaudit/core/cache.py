"""
Incremental scan cache — keyed by file content hash + plugin identity + config.

Every scan re-analysing every file from scratch makes the slowest plugins
(sast, secrets) painfully slow on large monorepos even when 99% of files are
unchanged since the last run. This cache lets file-level plugins skip
re-analysing files whose content (and the plugin's own config) hasn't changed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from secureaudit.core.models import Finding

if TYPE_CHECKING:
    from secureaudit.plugins import BasePlugin

_CACHE_SCHEMA_VERSION = 1
_DEFAULT_CACHE_DIR = ".secureaudit-cache"
_CACHE_FILE = "cache.json"

# Exported so plugins can hard-exclude the cache dir from their own file
# walks regardless of user-configured exclude_paths — a custom exclude_paths
# list that omits this would otherwise cause the cache to recursively scan
# (and pollute) its own stored evidence text on every subsequent run.
CACHE_DIR_NAME = _DEFAULT_CACHE_DIR


def default_cache_path(target: str | Path) -> Path:
    return Path(target) / _DEFAULT_CACHE_DIR / _CACHE_FILE


def hash_file(path: Path) -> str | None:
    """SHA-256 of file content. Returns None if the file can't be read."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()


def hash_config(config: dict) -> str:
    """Stable short hash of a plugin config dict — changing config invalidates cache entries."""
    serialised = json.dumps(config, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()[:16]


def cache_key(plugin_name: str, schema_version: int, config_hash: str, file_hash: str) -> str:
    raw = f"{plugin_name}:v{schema_version}:{config_hash}:{file_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


class FileCache:
    """Loads, queries, and persists the on-disk incremental scan cache."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._entries: dict[str, list[dict]] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if data.get("version") == _CACHE_SCHEMA_VERSION:
            self._entries = data.get("entries", {})

    def get(self, key: str) -> list[dict] | None:
        return self._entries.get(key)

    def set(self, key: str, findings: list[dict]) -> None:
        self._entries[key] = findings
        self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": _CACHE_SCHEMA_VERSION, "entries": self._entries}
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        self._dirty = False

    def clear(self) -> None:
        self._entries = {}
        self._dirty = True

    @property
    def entry_count(self) -> int:
        return len(self._entries)


def scan_with_cache(
    plugin: BasePlugin,
    files: list[Path],
    scan_one: Callable[[Path], list[Finding]],
) -> list[Finding]:
    """Run scan_one(file) for each file, reusing cached results where the file's
    content hash and the plugin's config hash both match a previous run.

    Falls back to scanning every file (no caching) if plugin.cache is None.
    """
    cache = plugin.cache
    if cache is None:
        results: list[Finding] = []
        for f in files:
            results.extend(scan_one(f))
        return results

    config_hash = hash_config(plugin.plugin_config)
    all_findings: list[Finding] = []

    for f in files:
        file_hash = hash_file(f)
        if file_hash is None:
            # Unreadable file — never cache, always attempt fresh (and let
            # scan_one decide how to handle the read failure).
            all_findings.extend(scan_one(f))
            continue

        key = cache_key(plugin.name, plugin.schema_version, config_hash, file_hash)
        cached = cache.get(key)
        if cached is not None:
            all_findings.extend(Finding.from_dict(d) for d in cached)
            continue

        fresh = scan_one(f)
        cache.set(key, [finding.to_dict() for finding in fresh])
        all_findings.extend(fresh)

    return all_findings


def cache_stats(
    plugin: BasePlugin, files: list[Path]
) -> tuple[int, int]:
    """Return (hits, misses) for the given files without mutating anything —
    useful for reporting cache effectiveness without performing a scan."""
    cache = plugin.cache
    if cache is None:
        return 0, len(files)

    config_hash = hash_config(plugin.plugin_config)
    hits = 0
    misses = 0
    for f in files:
        file_hash = hash_file(f)
        if file_hash is None:
            misses += 1
            continue
        key = cache_key(plugin.name, plugin.schema_version, config_hash, file_hash)
        if cache.get(key) is not None:
            hits += 1
        else:
            misses += 1
    return hits, misses

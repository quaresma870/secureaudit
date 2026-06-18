"""
Audit engine — orchestrates plugin execution and aggregates results.
Plugins run in parallel using ThreadPoolExecutor for faster scans.
"""

from __future__ import annotations

import importlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from secureaudit.core.config import Config
from secureaudit.core.models import AuditResult, PluginResult

# Auto-import all plugins to register them
_PLUGIN_MODULES = [
    "secureaudit.plugins.secrets",
    "secureaudit.plugins.cve",
    "secureaudit.plugins.filesystem",
    "secureaudit.plugins.http_headers",
    "secureaudit.plugins.network",
    "secureaudit.plugins.policy",
    "secureaudit.plugins.cors",
    "secureaudit.plugins.git_history",
    "secureaudit.plugins.sast",
    "secureaudit.plugins.malware",
    "secureaudit.plugins.trivy",
]


def _load_plugins() -> None:
    for module in _PLUGIN_MODULES:
        try:
            importlib.import_module(module)
        except ImportError:
            pass


_load_plugins()


class AuditEngine:
    def __init__(self, config: Config, workers: int = 6):
        self.config = config
        self.workers = workers

    def run(self, target: str | Path, plugins: list[str] | None = None) -> AuditResult:
        from secureaudit.plugins import get_plugin
        target = Path(target).resolve()
        plugin_names = plugins or self.config.plugins

        result = AuditResult(target=str(target))
        start = time.monotonic()

        # Instantiate plugins before parallel execution (registry lookup is not thread-safe)
        plugin_instances = []
        for name in plugin_names:
            try:
                plugin_instances.append((name, get_plugin(name, self.config)))
            except Exception as exc:
                result.plugin_results.append(PluginResult(plugin=name, error=str(exc)))

        # Run plugins in parallel
        with ThreadPoolExecutor(max_workers=min(self.workers, len(plugin_instances))) as executor:
            futures = {
                executor.submit(plugin.run, target): name
                for name, plugin in plugin_instances
            }
            # Preserve original order in results
            ordered: dict[str, PluginResult] = {}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    ordered[name] = future.result()
                except Exception as exc:
                    ordered[name] = PluginResult(plugin=name, error=str(exc))

        # Append in original plugin_names order
        for name, _ in plugin_instances:
            if name in ordered:
                result.plugin_results.append(ordered[name])

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

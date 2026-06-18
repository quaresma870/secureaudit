"""
Audit engine — orchestrates plugin execution and aggregates results.
"""

from __future__ import annotations

import importlib
import time
from pathlib import Path

from secureaudit.core.config import Config
from secureaudit.core.models import AuditResult
from secureaudit.plugins import get_plugin

# Auto-import all plugins to register them
_PLUGIN_MODULES = [
    "secureaudit.plugins.secrets",
    "secureaudit.plugins.cve",
    "secureaudit.plugins.filesystem",
    "secureaudit.plugins.http_headers",
    "secureaudit.plugins.network",
    "secureaudit.plugins.policy",
]


def _load_plugins() -> None:
    for module in _PLUGIN_MODULES:
        try:
            importlib.import_module(module)
        except ImportError:
            pass


_load_plugins()


class AuditEngine:
    def __init__(self, config: Config):
        self.config = config

    def run(self, target: str | Path, plugins: list[str] | None = None) -> AuditResult:
        target = Path(target).resolve()
        plugin_names = plugins or self.config.plugins

        result = AuditResult(target=str(target))
        start = time.monotonic()

        for name in plugin_names:
            try:
                plugin = get_plugin(name, self.config)
                plugin_result = plugin.run(target)
                result.plugin_results.append(plugin_result)
            except Exception as exc:
                from secureaudit.core.models import PluginResult
                result.plugin_results.append(
                    PluginResult(plugin=name, error=str(exc))
                )

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

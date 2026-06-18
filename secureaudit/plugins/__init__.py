"""
Plugin base class and registry.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from pathlib import Path

from secureaudit.core.config import Config
from secureaudit.core.models import PluginResult


class BasePlugin(ABC):
    """All audit plugins extend this class."""

    name: str = "base"
    description: str = ""

    def __init__(self, config: Config):
        self.config = config
        self.plugin_config = config.plugin_config(self.name)

    def run(self, target: str | Path) -> PluginResult:
        """Run the plugin against a target. Catches exceptions gracefully."""
        start = time.monotonic()
        try:
            result = self.audit(target)
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            return PluginResult(plugin=self.name, error=str(exc), duration_ms=elapsed)
        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    @abstractmethod
    def audit(self, target: str | Path) -> PluginResult:
        """Implement the actual audit logic."""


# ── Registry ──────────────────────────────────────────────────────────────────

_REGISTRY: dict[str, type[BasePlugin]] = {}


def register(cls: type[BasePlugin]) -> type[BasePlugin]:
    """Decorator to register a plugin."""
    _REGISTRY[cls.name] = cls
    return cls


def get_plugin(name: str, config: Config) -> BasePlugin:
    if name not in _REGISTRY:
        raise ValueError(f"Unknown plugin '{name}'. Available: {', '.join(_REGISTRY)}")
    return _REGISTRY[name](config)


def available_plugins() -> list[str]:
    return list(_REGISTRY.keys())

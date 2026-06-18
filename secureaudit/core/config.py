"""
Config — loads secureaudit.yml from the target directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_DEFAULTS: dict[str, Any] = {
    "plugins": ["secrets", "cve", "filesystem", "http", "network", "policy"],
    "fail_below": 70,
    "exclude_paths": [".git", "node_modules", ".venv", "__pycache__", "dist", "build"],
    "secrets": {
        "exclude_extensions": [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                               ".pdf", ".zip", ".tar", ".gz", ".woff", ".woff2"],
        "max_file_size_kb": 512,
    },
    "cve": {
        "ecosystems": ["PyPI", "npm", "Go", "Maven", "RubyGems", "Cargo"],
        "fail_on_severity": ["CRITICAL", "HIGH"],
    },
    "http": {
        "timeout": 10,
        "verify_ssl": True,
    },
    "network": {
        "ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306,
                  5432, 5900, 6379, 8080, 8443, 27017],
        "timeout": 1,
    },
    "policy": {
        "ssl_expiry_warning_days": 30,
    },
    "report": {
        "output_dir": "./secureaudit-reports",
        "formats": ["html", "json"],
    },
}


class Config:
    def __init__(self, data: dict[str, Any]):
        self._data = data

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        val = self._data
        for k in keys:
            if not isinstance(val, dict):
                return default
            val = val.get(k, default)
        return val

    @property
    def plugins(self) -> list[str]:
        return self._data.get("plugins", _DEFAULTS["plugins"])

    @property
    def fail_below(self) -> int:
        return int(self._data.get("fail_below", _DEFAULTS["fail_below"]))

    @property
    def exclude_paths(self) -> list[str]:
        return self._data.get("exclude_paths", _DEFAULTS["exclude_paths"])

    def plugin_config(self, plugin: str) -> dict[str, Any]:
        return self._data.get(plugin, _DEFAULTS.get(plugin, {}))


def load_config(path: str | Path | None = None) -> Config:
    """Load config from secureaudit.yml, falling back to defaults."""
    data = dict(_DEFAULTS)

    if path is None:
        path = Path("secureaudit.yml")

    cfg_path = Path(path)
    if cfg_path.exists():
        with open(cfg_path, encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        # Deep merge
        for key, val in user_cfg.items():
            if isinstance(val, dict) and isinstance(data.get(key), dict):
                data[key] = {**data[key], **val}
            else:
                data[key] = val

    return Config(data)

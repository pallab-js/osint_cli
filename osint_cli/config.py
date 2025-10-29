"""
User configuration management for OSINT CLI.
Stores and loads JSON config from ~/.osint_cli/config.json by default.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG: Dict[str, Any] = {
    "preferences": {
        "prefer_offline": False,
        "color_output": True,
        "report_format": "txt"
    },
    "network": {
        "timeout_seconds": 5,
        "max_concurrency": 4,
        "rate_limit_per_sec": 1
    },
    "features": {
        "enable_whois": True,
        "enable_dns": True,
        "enable_ssl": True,
        "enable_social": True,
        "enable_breach": False,
        "enable_tor": False
    },
    "paths": {
        "data_dir": "data",
        "cache_dir": ".cache"
    },
    "keys": {
        "hibp_api_key": "",
        "dehashed_api_key": "",
        "dehashed_email": ""
    }
}


def get_default_config_path() -> Path:
    home = Path(os.environ.get("HOME", str(Path.home())))
    return home / ".osint_cli" / "config.json"


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    path = Path(config_path) if config_path else get_default_config_path()
    if not path.exists():
        return DEFAULT_CONFIG.copy()
    try:
        with open(path, "r") as f:
            data = json.load(f)
            # Shallow merge onto defaults to ensure missing keys get defaults
            cfg = DEFAULT_CONFIG.copy()
            for k, v in data.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    merged = cfg[k].copy()
                    merged.update(v)
                    cfg[k] = merged
                else:
                    cfg[k] = v
            return cfg
    except Exception:
        # On error, fall back to defaults
        return DEFAULT_CONFIG.copy()


def save_default_config(config_path: Optional[str] = None) -> Path:
    path = Path(config_path) if config_path else get_default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    return path


def get_setting(config: Dict[str, Any], dotted_path: str, default: Any = None) -> Any:
    parts = dotted_path.split(".")
    cur: Any = config
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

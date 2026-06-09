"""Simple config store for BPC CLI defaults."""
import json
from pathlib import Path

CONFIG_FILE = Path.home() / ".bpc" / "config.json"


def get_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def set_config(key: str, value: str) -> None:
    cfg = get_config()
    cfg[key] = value
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)

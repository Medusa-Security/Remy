import json
import tomlkit
from pathlib import Path
from .schema import Config
import keyring

CONFIG_DIR = Path.home() / ".remy"
CONFIG_FILE = CONFIG_DIR / "config.toml"


def _toml_to_dict(data) -> dict:
    """Recursively convert a tomlkit document/table to plain Python dicts/lists.

    tomlkit uses special wrapper types (String, Integer, Table, etc.) that look
    like native Python types but fail Pydantic's strict Literal validation.
    This converts them to real Python primitives before model_validate.
    """
    if hasattr(data, "unwrap"):
        # tomlkit >= 0.11 exposes .unwrap() which does a full deep unwrap
        try:
            return data.unwrap()
        except Exception:
            pass
    if isinstance(data, dict):
        return {k: _toml_to_dict(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_toml_to_dict(v) for v in data]
    # For primitive wrappers, convert via json round-trip as a reliable fallback
    try:
        return json.loads(json.dumps(data))
    except Exception:
        return data


def load_config() -> Config | None:
    if not CONFIG_FILE.exists():
        return None
    try:
        with open(CONFIG_FILE, "r") as f:
            raw = tomlkit.load(f)
            data = _toml_to_dict(raw)
            return Config.model_validate(data)
    except Exception:
        return None


def save_config(config: Config):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            doc = tomlkit.load(f)
    else:
        doc = tomlkit.document()

    doc["provider"] = config.provider
    doc["model"] = config.model
    if config.base_url:
        doc["base_url"] = config.base_url

    scan_defaults = tomlkit.table()
    scan_defaults["deep"] = config.scan_defaults.deep
    scan_defaults["max_file_size_kb"] = config.scan_defaults.max_file_size_kb
    scan_defaults["respect_gitignore"] = config.scan_defaults.respect_gitignore

    doc["scan_defaults"] = scan_defaults

    with open(CONFIG_FILE, "w") as f:
        tomlkit.dump(doc, f)


def get_api_key(provider: str) -> str | None:
    try:
        return keyring.get_password("remy-agent", f"{provider}_api_key")
    except Exception:
        return None


def set_api_key(provider: str, api_key: str):
    if not api_key:
        return
    try:
        keyring.set_password("remy-agent", f"{provider}_api_key", api_key)
    except Exception:
        pass

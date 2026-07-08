"""Tests for config store read/write."""

import pytest
import tomlkit
from pathlib import Path

from remy.config.schema import Config, ScanDefaults


class TestConfigStore:
    """Test config save/load by writing directly to temp paths."""

    def _save_to(self, cfg: Config, path: Path) -> None:
        """Replicate save_config logic writing to an explicit path."""
        doc = tomlkit.document()
        doc["provider"] = cfg.provider
        doc["model"] = cfg.model
        if cfg.base_url:
            doc["base_url"] = cfg.base_url
        sd = tomlkit.table()
        sd["deep"] = cfg.scan_defaults.deep
        sd["max_file_size_kb"] = cfg.scan_defaults.max_file_size_kb
        sd["respect_gitignore"] = cfg.scan_defaults.respect_gitignore
        doc["scan_defaults"] = sd
        path.write_text(tomlkit.dumps(doc), encoding="utf-8")

    def _load_from(self, path: Path):
        """Replicate load_config logic reading from an explicit path."""
        if not path.exists():
            return None
        import json as _json

        try:
            raw = tomlkit.loads(path.read_text(encoding="utf-8"))
            # Deep-convert tomlkit wrappers to plain Python types for Pydantic
            if hasattr(raw, "unwrap"):
                data = raw.unwrap()
            else:
                data = _json.loads(_json.dumps(raw))
            return Config.model_validate(data)
        except Exception:
            return None

    def test_save_and_load_roundtrip(self, tmp_path):
        """Config written to disk should be loadable and equal."""
        config_file = tmp_path / "config.toml"
        cfg = Config(
            provider="openai",
            model="gpt-4o",
            base_url=None,
            scan_defaults=ScanDefaults(deep=True, max_file_size_kb=500),
        )

        self._save_to(cfg, config_file)
        loaded = self._load_from(config_file)

        assert loaded is not None
        assert loaded.provider == "openai"
        assert loaded.model == "gpt-4o"
        assert loaded.scan_defaults.deep is True
        assert loaded.scan_defaults.max_file_size_kb == 500

    def test_load_returns_none_when_no_file(self, tmp_path):
        config_file = tmp_path / "nonexistent.toml"
        result = self._load_from(config_file)
        assert result is None

    def test_save_preserves_base_url(self, tmp_path):
        config_file = tmp_path / "config.toml"
        cfg = Config(
            provider="ollama",
            model="llama3.2",
            base_url="http://localhost:11434",
            scan_defaults=ScanDefaults(),
        )
        self._save_to(cfg, config_file)
        loaded = self._load_from(config_file)

        assert loaded is not None
        assert loaded.base_url == "http://localhost:11434"

    def test_load_returns_none_on_invalid_toml(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text("this is not valid = toml [[\n")
        result = self._load_from(config_file)
        assert result is None

    def test_save_all_providers_valid(self, tmp_path):
        """Each supported provider value should survive a roundtrip."""
        for provider in [
            "openrouter",
            "groq",
            "openai",
            "anthropic",
            "xai",
            "nvidia_nim",
            "ollama",
        ]:
            config_file = tmp_path / f"config_{provider}.toml"
            cfg = Config(
                provider=provider, model="test-model", scan_defaults=ScanDefaults()
            )
            self._save_to(cfg, config_file)
            loaded = self._load_from(config_file)
            assert loaded is not None
            assert loaded.provider == provider

    def test_scan_defaults_roundtrip(self, tmp_path):
        config_file = tmp_path / "config.toml"
        cfg = Config(
            provider="groq",
            model="llama-3.3-70b-versatile",
            scan_defaults=ScanDefaults(
                deep=True,
                max_file_size_kb=2000,
                respect_gitignore=False,
            ),
        )
        self._save_to(cfg, config_file)
        loaded = self._load_from(config_file)
        assert loaded is not None
        assert loaded.scan_defaults.deep is True
        assert loaded.scan_defaults.max_file_size_kb == 2000
        assert loaded.scan_defaults.respect_gitignore is False

    def test_get_api_key_returns_none_when_not_set(self):
        """get_api_key should return None gracefully when no key is stored."""
        from remy.config.store import get_api_key

        # Use a provider name that won't have a real key in test environment
        result = get_api_key("__remy_test_provider_xyz__")
        assert result is None

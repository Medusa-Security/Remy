"""Target descriptor for the Medusa dynamic agents.

Unlike Remy's static scanners, the Medusa agents need a *running* system to
test against. A :class:`MedusaTarget` captures everything they need: where
the app lives, how to authenticate, and (optionally) an OpenAPI spec so the
API fuzzer and workflow agent know the surface without guessing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class MedusaTarget:
    base_url: str
    openapi_spec: Optional[dict] = None
    auth_token: Optional[str] = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    timeout: float = 15.0

    @property
    def auth_headers(self) -> dict:
        if not self.auth_token:
            return dict(self.headers)
        hdr = {self.auth_header: f"{self.auth_scheme} {self.auth_token}"}
        hdr.update(self.headers)
        return hdr

    @classmethod
    def from_spec_file(
        cls, base_url: str, spec_path: Optional[str] = None, **kw: object
    ) -> "MedusaTarget":
        spec: Optional[dict] = None
        if spec_path:
            p = Path(spec_path)
            text = p.read_text(encoding="utf-8")
            spec = (
                yaml.safe_load(text)
                if p.suffix in (".yaml", ".yml")
                else json.loads(text)
            )
        return cls(base_url=base_url, openapi_spec=spec, **kw)

    def endpoints_from_spec(self) -> list[dict]:
        """Flatten an OpenAPI spec into a list of {method, path, params} dicts."""
        if not self.openapi_spec:
            return []
        out: list[dict] = []
        paths = self.openapi_spec.get("paths", {})
        for path, methods in paths.items():
            for method, op in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue
                params = op.get("parameters", []) or []
                body_props = (
                    op.get("requestBody", {})
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                    .get("properties", {})
                )
                out.append(
                    {
                        "method": method.upper(),
                        "path": path,
                        "params": params,
                        "body_props": list(body_props.keys()),
                    }
                )
        return out

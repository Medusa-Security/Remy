"""Module dependency graph for Remy.

Parses Python ``import``/``from`` and JS/TS ``import``/``require`` statements to
discover which files depend on which. This single graph powers two features:

* **Blast radius** — how many files import a file that has a finding.
* **PR-diff mode** — scan changed files *and* every file that transitively
  depends on them, so a change's true test surface is covered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_PY_IMPORT = re.compile(r"^\s*(?:import\s+([\w\.]+)|from\s+([\w\.]+)\s+import\s+)")
_REL_IMPORT = re.compile(r"""from\s+['"]([.\w/]+)['"]|import\s+['"]([.\w/]+)['"]|require\(\s*['"]([.\w/]+)['"]\s*\)""")

_JS_EXTS = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")


@dataclass
class DependencyGraph:
    """Maps each file to the set of files that import it (its dependents)."""

    importers: dict[str, set[str]] = field(default_factory=dict)

    def dependents(self, file: str, max_depth: int = 12) -> set[str]:
        """Transitive set of files that import ``file`` (directly or indirectly)."""
        out: set[str] = set()
        frontier = {file}
        for _ in range(max_depth):
            nxt: set[str] = set()
            for f in frontier:
                for dep in self.importers.get(f, ()):
                    if dep not in out and dep != file:
                        out.add(dep)
                        nxt.add(dep)
            frontier = nxt
            if not frontier:
                break
        return out


def build_dependency_graph(root: str | Path) -> DependencyGraph:
    root = Path(root)
    py_modules = _python_module_map(root)
    graph = DependencyGraph()

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".py":
            _index_python(path, root, py_modules, graph)
        elif path.suffix in _JS_EXTS:
            _index_js(path, root, graph)
    return graph


# ── Python ────────────────────────────────────────────────────────────────────


def _python_module_map(root: Path) -> dict[str, str]:
    """Map dotted module name -> absolute file path for every .py file."""
    out: dict[str, str] = {}
    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        parts = list(rel.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        module = ".".join(parts)
        if module:
            out.setdefault(module, str(path))
            # also register the package prefix so `from pkg import x` resolves
            for i in range(len(parts) - 1, 0, -1):
                out.setdefault(".".join(parts[:i]), str(path))
    return out


def _resolve_python(module: str, py_modules: dict[str, str]) -> str | None:
    """Resolve a dotted import to a concrete file path, longest prefix wins."""
    if module in py_modules:
        return py_modules[module]
    # try stripping trailing components (from a.b import c -> a.b or a.b.c)
    parts = module.split(".")
    for i in range(len(parts), 0, -1):
        cand = ".".join(parts[:i])
        if cand in py_modules:
            return py_modules[cand]
    return None


def _index_python(path: Path, root: Path, py_modules: dict[str, str], graph: DependencyGraph) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    src = str(path)
    for line in text.splitlines():
        m = _PY_IMPORT.match(line)
        if not m:
            continue
        modules = [g for g in (m.group(1), m.group(2)) if g]
        for mod in modules:
            target = _resolve_python(mod, py_modules)
            if target and target != src:
                graph.importers.setdefault(target, set()).add(src)


# ── JavaScript / TypeScript ────────────────────────────────────────────────────


def _index_js(path: Path, root: Path, graph: DependencyGraph) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    src = str(path)
    for m in _REL_IMPORT.finditer(text):
        spec = m.group(1) or m.group(2) or m.group(3)
        if not spec or not spec.startswith("."):
            continue  # skip bare (node_modules) imports
        target = _resolve_relative(path, spec)
        if target and target != src:
            graph.importers.setdefault(str(target), set()).add(src)


def _resolve_relative(path: Path, spec: str) -> Path | None:
    base = path.parent / spec
    candidates = [base.with_suffix(base.suffix + ext) for ext in ("", ".js", ".ts", ".jsx", ".tsx", ".json")]
    candidates.append(base / "index.js")
    candidates.append(base / "index.ts")
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None
